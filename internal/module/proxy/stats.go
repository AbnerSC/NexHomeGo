package proxy

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"NexHomeGo/internal/core"
)

// 代理访问记录：按 天 × 域名 × 客户端IP 聚合落库（无逐请求明细，仅记录不做统计展示）。
// 应对长期海量记录（上亿行级）的设计与 Java 一致：
//   - 按月分表：写入 proxy_visit_stat_yyyymm 当月表，单表规模与索引深度可控；
//   - 保留期整表 DROP：过期月表直接 DROP TABLE，默认保留 12 个月，
//     app_config proxy.visit.retention_months 可调；
//   - 不阻塞转发线程：热路径 record 仅内存累加；归属地由 GeoResolver 离线库同步解析；
//   - 周期落库：每 30 秒把内存增量按目标月表分组、单事务批量 upsert；
//     落库失败退回内存下轮重试，不丢记录。

const (
	statsFlushSec      = 30
	statsKeyRetention  = "proxy.visit.retention_months"
	statsDefaultRetent = 12
	statsTablePrefix   = "proxy_visit_stat_"
)

var (
	pendingMu     sync.Mutex
	statsPending  = map[string]int64{} // key = day|host|ip -> 自上次落库以来累计的新增访问次数
	flushMu       sync.Mutex           // flush 串行 + tables/lastSweepDay 保护（与 engine 的 siteStats 锁 statsMu 区分）
	statsTables   = map[string]bool{}  // 已确认存在的月表后缀（yyyyMM）
	lastSweepDay  = ""                 // 上次月表巡检日：建新月表 + 清理超期表每日至多一次
	monthSuffixRe = regexp.MustCompile(`^\d{6}$`)
)

// statsInit 启动周期落库任务（ProxyService.init 时调用）
func statsInit() {
	core.Every(statsFlushSec, statsFlushSec, statsFlush)
}

// statsRecord 记录一次代理访问（热路径）：路由命中即计一次（含被访问控制拒绝的请求），
// 维度按请求 Host 域名 + 客户端 IP；归属地由离线库同步解析即时可得。
func statsRecord(host, ip string) {
	key := time.Now().Format("2006-01-02") + "|" + host + "|" + ip
	pendingMu.Lock()
	statsPending[key]++
	pendingMu.Unlock()
	geoRegionOf(ip) // 离线库微秒级检索 + 进程缓存，预热缓存供落库直接取
}

// statsFlushNow 立即落库（进程关停时调用，保留最后不足一个周期的增量）
func statsFlushNow() { statsFlush() }

type statsRow struct {
	day, host, ip string
	region        *Region
	hits          int64
}

// statsFlush 批量落库：先巡检月表，再排空内存增量按目标月表分组 upsert
func statsFlush() {
	flushMu.Lock()
	defer flushMu.Unlock()
	statsSweep()

	// 排空内存增量（整体交换：落库期间新访问进新桶，不丢不重）
	pendingMu.Lock()
	drained := statsPending
	statsPending = map[string]int64{}
	pendingMu.Unlock()

	// 按行 day 所属月表分组（跨月残留行各自落对应表）
	byTable := map[string][]*statsRow{}
	var order []string
	for k, v := range drained {
		if v <= 0 {
			continue // 无新增的旧桶：丢弃，防止 PENDING 无限增长
		}
		day, host, ip := splitStatsKey(k)
		g := geoRegionOf(ip) // 离线库同步检索（已缓存纯内存）
		t := tableOf(day)
		if _, ok := byTable[t]; !ok {
			order = append(order, t)
		}
		byTable[t] = append(byTable[t], &statsRow{day: day, host: host, ip: ip, region: g, hits: v})
	}
	sort.Strings(order) // LinkedHashMap 插入序近似：表名升序稳定执行

	for _, suffix := range order {
		rows := byTable[suffix]
		params := make([][]interface{}, 0, len(rows))
		for _, r := range rows {
			var country, province, city interface{}
			if r.region != nil {
				country, province, city = r.region.Country, r.region.Province, r.region.City
			}
			params = append(params, []interface{}{r.day, r.host, r.ip, country, province, city, r.hits})
		}
		table := statsTablePrefix + suffix
		if err := statsEnsureTable(suffix); err != nil {
			statsReturn(rows)
			core.LogWarn(core.LogProxy, "访问记录落库失败，将在下周期重试: "+err.Error())
			continue
		}
		_, err := core.UpdateBatch(fmt.Sprintf(`
INSERT INTO %s(day, host, ip, country, province, city, hits, last_at)
VALUES(?,?,?,?,?,?,?,datetime('now','localtime'))
ON CONFLICT(day, host, ip) DO UPDATE SET
    hits=hits+excluded.hits,
    last_at=excluded.last_at,
    country=COALESCE(NULLIF(%s.country,''), excluded.country),
    province=COALESCE(NULLIF(%s.province,''), excluded.province),
    city=COALESCE(NULLIF(%s.city,''), excluded.city)`, table, table, table, table), params)
		if err != nil { // 落库失败：退回内存，下周期重试，不丢记录
			statsReturn(rows)
			core.LogWarn(core.LogProxy, "访问记录落库失败，将在下周期重试: "+err.Error())
		}
	}
}

func statsReturn(rows []*statsRow) {
	pendingMu.Lock()
	defer pendingMu.Unlock()
	for _, r := range rows {
		statsPending[r.day+"|"+r.host+"|"+r.ip] += r.hits
	}
}

// statsSweep 月表巡检（每日至多一次）：确保当月表存在；登记现存月表；
// DROP 早于保留期的整月表——元数据级操作瞬时完成，规避大批量 DELETE 的写放大与碎片。
func statsSweep() {
	today := time.Now()
	day := today.Format("2006-01-02")
	if day == lastSweepDay {
		return
	}
	if err := statsEnsureTable(today.Format("200601")); err != nil {
		core.LogWarn(core.LogProxy, "访问记录月表巡检失败: "+err.Error())
		return
	}
	cutoff := today.AddDate(0, -statsRetentionMonths(), 0).Format("200601")
	rows, err := core.Query("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '" + statsTablePrefix + "%'")
	if err != nil {
		core.LogWarn(core.LogProxy, "访问记录月表巡检失败: "+err.Error())
		return
	}
	for _, r := range rows {
		name := strVal(r.Get("name"))
		if len(name) <= len(statsTablePrefix) {
			continue
		}
		suffix := name[len(statsTablePrefix):]
		if !monthSuffixRe.MatchString(suffix) {
			continue // 非月表命名（如旧版静态表）不处理
		}
		statsTables[suffix] = true
		if suffix < cutoff {
			if _, err := core.Update("DROP TABLE IF EXISTS " + name); err != nil {
				core.LogWarn(core.LogProxy, "访问记录月表巡检失败: "+err.Error())
				continue
			}
			delete(statsTables, suffix)
			core.LogInfo(core.LogProxy, "访问记录月表已超保留期，整表清理: "+name)
		}
	}
	lastSweepDay = day
}

// statsRetentionMonths 保留月数：app_config 可调，非法或缺省回退默认值
func statsRetentionMonths() int {
	v, err := core.GetConfig(statsKeyRetention)
	if err != nil {
		return statsDefaultRetent // 读取失败按默认值
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return statsDefaultRetent
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return statsDefaultRetent
	}
	if n > 120 {
		return 120
	}
	return n
}

// statsEnsureTable 确保月表存在（DDL 与原静态表结构一致，含缓存避免重复执行）
func statsEnsureTable(suffix string) error {
	if statsTables[suffix] {
		return nil
	}
	table := statsTablePrefix + suffix
	err := core.ExecScript(fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
    day      TEXT NOT NULL,
    host     TEXT NOT NULL,
    ip       TEXT NOT NULL,
    country  TEXT,
    province TEXT,
    city     TEXT,
    hits     INTEGER NOT NULL DEFAULT 0,
    last_at  TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    PRIMARY KEY (day, host, ip)
)`, table))
	if err != nil {
		return err
	}
	statsTables[suffix] = true
	return nil
}

// tableOf day(yyyy-MM-dd) -> 月表后缀
func tableOf(day string) string {
	return strings.ReplaceAll(day[0:7], "-", "")
}

// splitStatsKey 解析复合键 day|host|ip（host/ip 不含 '|'）
func splitStatsKey(key string) (string, string, string) {
	i1 := strings.IndexByte(key, '|')
	i2 := strings.Index(key[i1+1:], "|") + i1 + 1
	return key[:i1], key[i1+1 : i2], key[i2+1:]
}
