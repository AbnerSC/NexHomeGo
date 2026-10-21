package web

import (
	"strings"
	"time"

	"NexHomeGo/internal/core"
)

// 统一状态仪表盘聚合：把分散在各模块的关键状态汇总成一次请求，供首页总览面板展示。
// 全部只读统计；Docker 概览失败（未挂载 sock 等）容忍降级，不影响其余板块。
// 板块顺序与 Java DashboardService.summary 完全一致：system, ddns, stun, cert, monitor, docker, proxy, visits。

const (
	certWarnDays = 21
	visitDays    = 7
	visitPrefix  = "proxy_visit_stat_"
	regionExpr   = "CASE WHEN COALESCE(country,'')='' THEN '未知' " +
		"WHEN country='中国' AND COALESCE(province,'')!='' THEN province " +
		"ELSE country END"
)

// DockerSummaryProvider 由 Docker 模块在启动时注入，返回其概览对象；未注入或失败时降级为空对象。
var DockerSummaryProvider func() *core.Row

// ProxyListeningProvider 由反向代理模块注入，返回监听端口是否已绑定（>0）。
var ProxyListeningProvider func() bool

// DashboardSummary 聚合各板块状态。
func DashboardSummary() *core.Row {
	d := core.NewRow()
	d.Set("system", dashSystem())
	d.Set("ddns", dashCount("ddns_task", "SUM(CASE WHEN last_status LIKE 'FAIL%' THEN 1 ELSE 0 END)", "enabled"))
	d.Set("stun", dashStun())
	d.Set("cert", dashCert())
	d.Set("monitor", dashMonitor())
	d.Set("docker", dashDocker())
	d.Set("proxy", dashProxy())
	d.Set("visits", dashVisits())
	return d
}

func dashSystem() *core.Row {
	m := core.NewRow()
	m.Set("uptimeSec", int64(time.Since(bootTime).Seconds()))
	m.Set("port", HTTPPort())
	m.Set("httpsActive", HTTPSActive())
	return m
}

// dashCount 通用计数：total + enabled + failed（failedExpr 为统计失败的 SQL 表达式）。
func dashCount(table, failedExpr, enabledCol string) *core.Row {
	row, _ := core.QueryOne("SELECT COUNT(*) total, "+
		"SUM(CASE WHEN "+enabledCol+"=1 THEN 1 ELSE 0 END) enabled, "+
		failedExpr+" failed FROM "+table)
	return numMap(row, "total", "enabled", "failed")
}

func dashStun() *core.Row {
	row, _ := core.QueryOne("SELECT COUNT(*) total, " +
		"SUM(CASE WHEN status='RUNNING' THEN 1 ELSE 0 END) running, " +
		"SUM(CASE WHEN status='ERROR' THEN 1 ELSE 0 END) failed FROM stun_task")
	return numMap(row, "total", "running", "failed")
}

func dashMonitor() *core.Row {
	row, _ := core.QueryOne("SELECT COUNT(*) total, " +
		"SUM(CASE WHEN enabled=1 THEN 1 ELSE 0 END) enabled, " +
		"SUM(CASE WHEN last_status='DOWN' THEN 1 ELSE 0 END) down, " +
		"SUM(CASE WHEN last_status='UP' THEN 1 ELSE 0 END) up FROM monitor_task")
	return numMap(row, "total", "enabled", "down", "up")
}

// dashCert 证书：总数、已签发、临期（<=21 天）、临期明细（含剩余天数）。
func dashCert() *core.Row {
	tasks, _ := core.Query("SELECT id, name, status, not_after FROM cert_task ORDER BY id")
	expiring := core.NewRowList()
	issued, soon := 0, 0
	today := dateOnly(time.Now())
	for _, t := range tasks {
		status := str(t.Get("status"))
		if status == "ISSUED" {
			issued++
		}
		days := daysRemaining(str(t.Get("not_after")), today)
		if status == "ISSUED" && days >= 0 && days <= certWarnDays {
			soon++
			e := core.NewRow()
			e.Set("id", t.Get("id"))
			e.Set("name", str(t.Get("name")))
			e.Set("not_after", str(t.Get("not_after")))
			e.Set("daysLeft", days)
			expiring.Append(e)
		}
	}
	m := core.NewRow()
	m.Set("total", len(tasks))
	m.Set("issued", issued)
	m.Set("expiringSoon", soon)
	m.Set("warnDays", certWarnDays)
	m.Set("expiringList", expiring)
	return m
}

// dashDocker 由 Docker 模块提供；未注入或返回 nil 时降级为空对象（等价 Java 容错）。
func dashDocker() *core.Row {
	if DockerSummaryProvider != nil {
		if v := DockerSummaryProvider(); v != nil {
			return v
		}
	}
	return core.NewRow()
}

// dashProxy 代理站点：启用/总数 + 监听状态（模块未注入时视为未监听）。
func dashProxy() *core.Row {
	row, _ := core.QueryOne("SELECT COUNT(*) total, " +
		"SUM(CASE WHEN enabled=1 THEN 1 ELSE 0 END) enabled FROM proxy_site")
	m := numMap(row, "total", "enabled")
	listening := false
	if ProxyListeningProvider != nil {
		listening = ProxyListeningProvider()
	}
	m.Set("listening", listening)
	return m
}

// dashVisits 代理访问统计（最近 7 天）：每日总访问、网站 TOP10、来源地区 TOP10。
func dashVisits() *core.Row {
	today := dateOnly(time.Now())
	days := make([]string, 0, visitDays)
	for i := visitDays - 1; i >= 0; i-- {
		days = append(days, today.AddDate(0, 0, -i).Format("2006-01-02"))
	}
	from, to := days[0], days[len(days)-1]
	union := visitUnion(from, to)

	daily := core.NewRowList()
	topSites := core.NewRowList()
	topRegions := core.NewRowList()
	var total int64
	if union != "" {
		dayHits := map[string]int64{}
		if rows, err := core.Query("SELECT day, SUM(hits) hits FROM (" + union +
			") WHERE day BETWEEN '" + from + "' AND '" + to + "' GROUP BY day"); err == nil {
			for _, r := range rows {
				dayHits[str(r.Get("day"))] = toInt64(r.Get("hits"))
			}
		}
		for _, day := range days {
			hits := dayHits[day]
			total += hits
			daily.Append(core.NewRow().Set("day", day).Set("hits", hits))
		}
		if rows, err := core.Query("SELECT host, SUM(hits) hits FROM (" + union +
			") WHERE day BETWEEN '" + from + "' AND '" + to +
			"' GROUP BY host ORDER BY hits DESC LIMIT 10"); err == nil {
			for _, r := range rows {
				topSites.Append(core.NewRow().Set("name", str(r.Get("host"))).Set("hits", toInt64(r.Get("hits"))))
			}
		}
		if rows, err := core.Query("SELECT "+regionExpr+" region, SUM(hits) hits FROM ("+union+
			") WHERE day BETWEEN '" + from + "' AND '" + to +
			"' GROUP BY region ORDER BY hits DESC LIMIT 10"); err == nil {
			for _, r := range rows {
				topRegions.Append(core.NewRow().Set("name", str(r.Get("region"))).Set("hits", toInt64(r.Get("hits"))))
			}
		}
	} else {
		for _, day := range days {
			daily.Append(core.NewRow().Set("day", day).Set("hits", int64(0)))
		}
	}
	m := core.NewRow()
	m.Set("total", total)
	m.Set("days", daily)
	m.Set("topSites", topSites)
	m.Set("topRegions", topRegions)
	return m
}

// visitUnion 7 天窗口命中的访问月表 UNION 视图（仅拼接真实存在的表，跨月至多 2 张）。
func visitUnion(from, to string) string {
	rows, err := core.Query("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '" +
		visitPrefix + "%'")
	if err != nil {
		return ""
	}
	existing := map[string]bool{}
	for _, r := range rows {
		existing[str(r.Get("name"))] = true
	}
	startMonth := from[:7] // yyyy-MM
	endMonth := to[:7]
	var sb strings.Builder
	cur := startMonth
	for {
		table := visitPrefix + strings.ReplaceAll(cur, "-", "")
		if existing[table] {
			if sb.Len() > 0 {
				sb.WriteString(" UNION ALL ")
			}
			sb.WriteString("SELECT day, host, country, province, hits FROM " + table)
		}
		if cur == endMonth {
			break
		}
		t, e := time.Parse("2006-01", cur)
		if e != nil {
			break
		}
		cur = t.AddDate(0, 1, 0).Format("2006-01")
		if cur > endMonth {
			break
		}
	}
	return sb.String()
}

func daysRemaining(notAfter string, today time.Time) int64 {
	if len(notAfter) < 10 {
		return -1
	}
	t, err := time.Parse("2006-01-02", notAfter[:10])
	if err != nil {
		return -1
	}
	return int64(t.Sub(dateOnly(today)).Hours() / 24)
}

func dateOnly(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
}

func numMap(row *core.Row, keys ...string) *core.Row {
	m := core.NewRow()
	for _, k := range keys {
		var v int64
		if row != nil {
			v = toInt64(row.Get(k))
		}
		m.Set(k, v)
	}
	return m
}
