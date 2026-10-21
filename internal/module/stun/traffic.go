package stun

// 穿透通道流量统计：按任务累积转发字节数（双向合计），连接重建不清零。
// 复刻 Java TrafficStats，设计要点：
//   - 不影响转发性能：热路径 record 仅做内存累加，不逐包写库；
//     时间桶键（时/天/月）每任务缓存 1 秒，避免逐块计算时间字符串
//     （Java 用无锁 LongAdder，Go 侧等价改用互斥锁保护的 map：转发块粒度毫秒级，
//     锁竞争可忽略，语义一致）
//   - 重建不清零：计数以 task_id 为维度累积，与 socket 生命周期无关，
//     链路轮换/弹跳重建/任务重启（同 id）均延续
//   - 周期落库：flush 每 30 秒把内存增量以单事务批量 upsert 到 stun_traffic，
//     按 TOTAL/HOUR/DAY/MONTH 归档；落库失败退回内存下轮重试，不丢统计
//   - 实时展示：查询把已落库值与内存未落库增量合并，展示接近实时

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"NexHomeGo/internal/core"
)

const trafficFlushSec = 30

var (
	trafficMu sync.Mutex
	// trafficPending 待落库增量：key = taskId|periodType|periodKey -> 该桶自上次落库以来累计的新增字节
	trafficPending = map[string]int64{}
	// trafficBuckets 每任务的时间桶键缓存：避免逐块计算时间字符串，键最多每 1 秒刷新一次
	trafficBuckets = map[int64]*trafficBucketKeys{}
)

// trafficBucketKeys 每任务缓存的当前时间桶键：TOTAL 键恒定，HOUR/DAY/MONTH 键随时间滚动（缓存 1s 降低计算频率）
// 字段访问统一在 trafficMu 保护下进行（热路径仅数次 map 查找，无额外竞争）
type trafficBucketKeys struct {
	taskID    int64
	totalKey  string
	hourKey   string
	dayKey    string
	monthKey  string
	keysUntil int64
}

// initTraffic 启动周期落库任务（进程启动时调用一次）
func initTraffic() {
	core.Every(trafficFlushSec, trafficFlushSec, flushTraffic)
}

// recordTraffic 记录一次转发的字节数（热路径）：按任务的 TOTAL/HOUR/DAY/MONTH 四个桶累加。
// 由 UDP 转发与 TCP 管道在每块数据发送后调用，成本仅数次 map 累加。
func recordTraffic(taskID int64, bytes int64) {
	if bytes <= 0 {
		return
	}
	trafficMu.Lock()
	b := trafficBuckets[taskID]
	if b == nil {
		b = &trafficBucketKeys{taskID: taskID, totalKey: fmt.Sprintf("%d|TOTAL|all", taskID)}
		trafficBuckets[taskID] = b
	}
	now := time.Now().UnixMilli()
	if now >= b.keysUntil {
		b.roll(now) // 时间桶滚动（最多每秒一次，锁内重算键）
	}
	totalKey, hourKey, dayKey, monthKey := b.totalKey, b.hourKey, b.dayKey, b.monthKey
	for _, k := range [4]string{totalKey, hourKey, dayKey, monthKey} {
		trafficPending[k] += bytes // 热路径仅内存累加，不逐包写库
	}
	trafficMu.Unlock()
}

// roll 重算当前时间桶键（本地时间，与 Java LocalDateTime.now 格式一致）；调用方持 trafficMu
func (b *trafficBucketKeys) roll(now int64) {
	t := time.Now()
	b.hourKey = fmt.Sprintf("%d|HOUR|%s", b.taskID, t.Format("2006-01-02 15"))
	b.dayKey = fmt.Sprintf("%d|DAY|%s", b.taskID, t.Format("2006-01-02"))
	b.monthKey = fmt.Sprintf("%d|MONTH|%s", b.taskID, t.Format("2006-01"))
	b.keysUntil = now + 1000
}

// trafficTotalBytes 任务累计总流量（已落库 + 内存实时增量），单位字节
func trafficTotalBytes(taskId int64) int64 {
	var db int64
	v, err := core.Scalar("SELECT bytes FROM stun_traffic WHERE task_id=? AND period_type='TOTAL' AND period_key='all'", taskId)
	if err == nil {
		if n, ok := v.(int64); ok {
			db = n
		}
	}
	// 查询失败：仅返回内存增量
	trafficMu.Lock()
	mem := trafficPending[fmt.Sprintf("%d|TOTAL|all", taskId)]
	trafficMu.Unlock()
	return db + mem
}

// trafficDetail 任务流量明细：总量 + 按小时/天/月归档序列（均合并内存未落库增量，按时间倒序）。
// 返回 Row{total,hours,days,months}，与 Java LinkedHashMap 输出顺序一致。
func trafficDetail(taskId int64) *core.Row {
	pend := trafficPendingFor(taskId)
	res := core.NewRow()
	res.Set("total", trafficTotalBytes(taskId))
	res.Set("hours", trafficSeries(taskId, "HOUR", pend, 24))
	res.Set("days", trafficSeries(taskId, "DAY", pend, 30))
	res.Set("months", trafficSeries(taskId, "MONTH", pend, 12))
	return res
}

// trafficClear 删除任务时清理其内存计数与落库数据
func trafficClear(taskId int64) {
	prefix := fmt.Sprintf("%d|", taskId)
	trafficMu.Lock()
	delete(trafficBuckets, taskId)
	for k := range trafficPending {
		if strings.HasPrefix(k, prefix) {
			delete(trafficPending, k)
		}
	}
	trafficMu.Unlock()
	if _, err := core.Update("DELETE FROM stun_traffic WHERE task_id=?", taskId); err != nil {
		core.LogWarn(core.LogStun, "清理任务流量统计失败: "+err.Error())
	}
}

// flushTrafficNow 立即落库（进程关停时调用，保留最后不足一个周期的增量）
func flushTrafficNow() {
	flushTraffic()
}

// trafficPendingFor 收集本任务当前全部内存增量，键为 periodType|periodKey
func trafficPendingFor(taskId int64) map[string]int64 {
	m := map[string]int64{}
	idStr := fmt.Sprintf("%d", taskId)
	trafficMu.Lock()
	defer trafficMu.Unlock()
	for k, v := range trafficPending {
		parts := splitTrafficKey(k)
		if parts[0] == idStr {
			m[parts[1]+"|"+parts[2]] += v
		}
	}
	return m
}

// trafficSeries 查询某维度时间序列（DB 已落库 + 内存增量合并，按 period_key 倒序取前 limit 条）
func trafficSeries(taskId int64, typ string, pend map[string]int64, limit int) []interface{} {
	map_ := map[string]int64{}
	rows, err := core.Query(
		"SELECT period_key, bytes FROM stun_traffic WHERE task_id=? AND period_type=? ORDER BY period_key DESC LIMIT ?",
		taskId, typ, limit)
	if err == nil {
		for _, r := range rows {
			key, _ := r.Get("period_key").(string)
			var bytes int64
			if n, ok := r.Get("bytes").(int64); ok {
				bytes = n
			}
			map_[key] = bytes
		}
	}
	// 查询失败：仅展示内存增量
	tp := typ + "|"
	for k, v := range pend {
		if strings.HasPrefix(k, tp) {
			map_[k[len(tp):]] += v
		}
	}
	keys := make([]string, 0, len(map_))
	for k := range map_ {
		keys = append(keys, k)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(keys)))
	out := make([]interface{}, 0, limit)
	for i, k := range keys {
		if i >= limit {
			break
		}
		m := core.NewRow()
		m.Set("key", k)
		m.Set("bytes", map_[k])
		out = append(out, m)
	}
	return out
}

// flushTraffic 批量落库：排空内存增量单事务 upsert 到 stun_traffic；失败退回内存下轮重试
func flushTraffic() {
	trafficMu.Lock()
	if len(trafficPending) == 0 {
		trafficMu.Unlock()
		return
	}
	type delta struct {
		key   string
		value int64
	}
	var deltas []delta
	paramsList := make([][]interface{}, 0, len(trafficPending))
	for k, v := range trafficPending {
		if v <= 0 {
			deltas = append(deltas, delta{k, 0}) // 旧时间桶已无新增：移除，防止 PENDING 无限增长
			continue
		}
		parts := splitTrafficKey(k)
		taskId, _ := strconv.ParseInt(parts[0], 10, 64)
		paramsList = append(paramsList, []interface{}{taskId, parts[1], parts[2], v})
		deltas = append(deltas, delta{k, v})
	}
	for _, d := range deltas {
		delete(trafficPending, d.key) // 排空：v<=0 直接丢弃，v>0 落库成功后不再回补
	}
	trafficMu.Unlock()

	if len(paramsList) == 0 {
		return
	}
	if _, err := core.UpdateBatch(`
		INSERT INTO stun_traffic(task_id, period_type, period_key, bytes, updated_at)
		VALUES(?,?,?,?,datetime('now','localtime'))
		ON CONFLICT(task_id, period_type, period_key)
		DO UPDATE SET bytes=bytes+excluded.bytes, updated_at=excluded.updated_at`, paramsList); err != nil {
		// 落库失败：退回内存，下周期重试，不丢统计
		trafficMu.Lock()
		for _, d := range deltas {
			if d.value > 0 {
				trafficPending[d.key] += d.value
			}
		}
		trafficMu.Unlock()
		core.LogWarn(core.LogStun, "流量统计落库失败，将在下周期重试: "+err.Error())
	}
}

// splitTrafficKey 解析复合键 taskId|periodType|periodKey（periodKey 含空格/冒号但不含 '|'）
func splitTrafficKey(key string) [3]string {
	i1 := strings.IndexByte(key, '|')
	i2 := strings.IndexByte(key[i1+1:], '|') + i1 + 1
	return [3]string{key[:i1], key[i1+1 : i2], key[i2+1:]}
}
