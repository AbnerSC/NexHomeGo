package proxy

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"NexHomeGo/internal/core"
)

// 代理文件缓存（模仿 nginx proxy_cache 的磁盘缓存，突破内存容量限制）。
// 布局：data/proxy-cache/{siteId}/{hash前2位}/{hash}.data 存响应体，同名 .meta 存状态码/响应头/过期时间等元数据；
// 写入先落 .tmp 临时文件，完成后原子 rename，避免半份缓存。内存索引（hash -> Entry）启动时扫描 .meta 重建，
// 缓存跨重启有效。过期与容量：TTL（上游 Cache-Control 优先或站点 ttlSec 兜底）+ nginx inactive 语义
// （长期未命中清理）+ 站点总容量 LRU 驱逐；后台周期任务统一执行。
// key = 站点id + method + 完整 URL（含查询串）；带 Authorization 头的请求不读不写（安全默认）。

var cacheRoot = func() string { return core.DataDir() + "/proxy-cache" }

// cacheEntry 一条缓存元数据（响应体在 file 中）
type cacheEntry struct {
	siteId     int64
	key        string
	file       string
	status     int
	headers    [][2]string
	size       int64
	expiresAt  int64 // 毫秒时间戳
	lastAccess int64 // 毫秒时间戳，命中时刷新
}

// cacheWriter 一次响应的旁路写入器（流式中继的同时 tee 到缓存文件）
type cacheWriter struct {
	siteId  int64
	key     string
	tmpPath string
	tmp     *os.File
	written int64
	failed  bool
}

var (
	cacheMu     sync.Mutex
	cacheIndex  = map[string]*cacheEntry{}
	cacheBytes  = map[int64]int64{}
	cacheHits   = map[int64]int64{}
	cacheMisses = map[int64]int64{}
	// 站点缓存策略（store 时登记，清理任务读取；缺省 256MB / 7 天 inactive）：[maxBytes, inactiveSec]
	cachePolicy = map[int64][2]int64{}
)

func nowMillis() int64 { return time.Now().UnixMilli() }

// cacheInit 启动初始化：扫描缓存目录重建内存索引，孤儿站点目录清理，并挂周期清理任务
func cacheInit(siteExists func(int64) bool) {
	cacheMu.Lock()
	if dir, err := os.Stat(cacheRoot()); err != nil || !dir.IsDir() {
		cacheMu.Unlock()
		return
	}
	now := nowMillis()
	siteDirs, err := os.ReadDir(cacheRoot())
	if err != nil {
		cacheMu.Unlock()
		core.LogError(core.LogProxy, "代理缓存初始化失败: "+err.Error())
		return
	}
	for _, d := range siteDirs {
		if !d.IsDir() {
			continue
		}
		siteId, err := strconv.ParseInt(d.Name(), 10, 64)
		if err != nil {
			continue
		}
		if !siteExists(siteId) {
			cacheMu.Unlock()
			cachePurgeSite(siteId) // 站点已删除：清掉整个缓存目录
			cacheMu.Lock()
			continue
		}
		siteDir := filepath.Join(cacheRoot(), d.Name())
		metas, _ := filepath.Glob(filepath.Join(siteDir, "*", "*.meta"))
		for _, mp := range metas {
			e, err := readMeta(mp, siteId)
			if err != nil {
				core.LogWarn(core.LogProxy, "缓存元数据解析失败（跳过）: "+mp+" "+err.Error())
				continue
			}
			if e == nil || e.expiresAt < now {
				deleteEntryFiles(e)
				continue
			}
			if _, err := os.Stat(e.file); err != nil {
				deleteEntryFiles(e)
				continue
			}
			cacheIndex[keyHash(e.key)] = e
			cacheBytes[siteId] += e.size
		}
	}
	core.LogInfo(core.LogProxy, fmt.Sprintf("代理文件缓存已加载：%d 项，共 %d MB", len(cacheIndex), cacheTotalBytesLocked()/1024/1024))
	cacheMu.Unlock()
	core.Every(60, 60, cacheCleanupOnce) // 每分钟：过期/inactive/容量清理
}

// cacheLookup 查缓存：命中返回 Entry（并刷新 lastAccess），未命中/过期返回 nil 并计数
func cacheLookup(siteId int64, key string, withAuth bool) *cacheEntry {
	if withAuth {
		return nil // 带 Authorization 不读缓存（安全默认）
	}
	cacheMu.Lock()
	defer cacheMu.Unlock()
	e := cacheIndex[keyHash(key)]
	if e == nil || e.siteId != siteId { // 站点路由切换后的陈旧条目按未命中处理
		cacheMisses[siteId]++
		return nil
	}
	if e.expiresAt < nowMillis() {
		cacheRemoveLocked(e)
		cacheMisses[siteId]++
		return nil
	}
	e.lastAccess = nowMillis()
	cacheHits[siteId]++
	return e
}

// cacheNewWriter 新建旁路写入器（.tmp 临时文件，finish 时原子改名入索引）；失败返回 nil
func cacheNewWriter(siteId int64, key string, adv *Advanced) *cacheWriter {
	dir := cacheDirFor(siteId, key)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		core.LogWarn(core.LogProxy, "创建缓存写入器失败: "+err.Error())
		return nil
	}
	hash := keyHash(key)
	tmpPath := filepath.Join(dir, hash+"."+randHex16()+".tmp")
	cacheMu.Lock()
	cachePolicy[siteId] = [2]int64{int64(adv.CacheMaxMB) * 1024 * 1024, int64(adv.CacheInactiveSec)}
	cacheMu.Unlock()
	return &cacheWriter{siteId: siteId, key: key, tmpPath: tmpPath}
}

// Append 追加一段响应体；写失败自动废弃缓存（已中继部分不受影响）
func (w *cacheWriter) Append(p []byte) {
	if w.failed || len(p) == 0 {
		return
	}
	if w.tmp == nil {
		f, err := os.OpenFile(w.tmpPath, os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			w.failed = true
			w.closeQuietly()
			deleteQuietly(w.tmpPath)
			return
		}
		w.tmp = f
	}
	for off := 0; off < len(p); {
		n, err := w.tmp.Write(p[off:])
		if err != nil || n <= 0 {
			w.failed = true
			break
		}
		off += n
	}
	if w.failed {
		w.closeQuietly()
		deleteQuietly(w.tmpPath)
		return
	}
	w.written += int64(len(p))
}

// Finish 响应正常结束：原子落盘并登记索引。返回是否成功入缓存
func (w *cacheWriter) Finish(status int, headers [][2]string, expiresAt int64) bool {
	w.closeQuietly()
	if w.failed || w.written <= 0 {
		deleteQuietly(w.tmpPath)
		return false
	}
	data := filepath.Join(filepath.Dir(w.tmpPath), keyHash(w.key)+".data")
	if err := os.Rename(w.tmpPath, data); err != nil {
		deleteQuietly(w.tmpPath)
		core.LogWarn(core.LogProxy, "缓存落盘失败: "+err.Error())
		return false
	}
	e := &cacheEntry{siteId: w.siteId, key: w.key, file: data, status: status,
		headers: headers, size: w.written, expiresAt: expiresAt, lastAccess: nowMillis()}
	if err := writeMeta(e); err != nil {
		deleteQuietly(data)
		core.LogWarn(core.LogProxy, "缓存落盘失败: "+err.Error())
		return false
	}
	cacheMu.Lock()
	cacheIndex[keyHash(e.key)] = e
	cacheBytes[e.siteId] += e.size
	cacheMu.Unlock()
	return true
}

// Abort 响应异常/放弃缓存：清理临时文件
func (w *cacheWriter) Abort() {
	w.closeQuietly()
	deleteQuietly(w.tmpPath)
}

func (w *cacheWriter) closeQuietly() {
	if w.tmp != nil {
		w.tmp.Close()
		w.tmp = nil
	}
}

// cacheBuildKey 缓存 key：method + 完整 URL（含查询串，scheme+host 由客户端请求 authority 提供）
func cacheBuildKey(method, url string) string { return method + " " + url }

// cachePurgeSite 清理某站点全部缓存（删除站点/手动 purge）
func cachePurgeSite(siteId int64) {
	cacheMu.Lock()
	for h, e := range cacheIndex {
		if e.siteId == siteId {
			delete(cacheIndex, h)
			deleteEntryFiles(e)
		}
	}
	delete(cacheBytes, siteId)
	delete(cacheHits, siteId)
	delete(cacheMisses, siteId)
	delete(cachePolicy, siteId)
	cacheMu.Unlock()
	dir := filepath.Join(cacheRoot(), strconv.FormatInt(siteId, 10))
	if st, err := os.Stat(dir); err == nil && st.IsDir() {
		if err := os.RemoveAll(dir); err != nil {
			core.LogWarn(core.LogProxy, fmt.Sprintf("清理站点 %d 缓存目录失败: %s", siteId, err.Error()))
		}
	}
}

// cacheCleanupOnce 周期清理：过期删除 -> inactive 驱逐 -> 站点容量 LRU 驱逐
func cacheCleanupOnce() {
	now := nowMillis()
	cacheMu.Lock()
	defer cacheMu.Unlock()
	var expired []*cacheEntry
	for _, e := range cacheIndex {
		if e.expiresAt < now {
			expired = append(expired, e)
		}
	}
	for _, e := range expired {
		cacheRemoveLocked(e)
	}
	bySite := map[int64][]*cacheEntry{}
	for _, e := range cacheIndex {
		bySite[e.siteId] = append(bySite[e.siteId], e)
	}
	for siteId, list := range bySite {
		policy := cachePolicy[siteId]
		if policy == [2]int64{} {
			policy = [2]int64{256 * 1024 * 1024, 604800} // 缺省 256MB / 7 天 inactive
		}
		inactiveMs := policy[1] * 1000
		var inactive []*cacheEntry
		for _, e := range list {
			if now-e.lastAccess > inactiveMs {
				inactive = append(inactive, e)
			}
		}
		for _, e := range inactive {
			cacheRemoveLocked(e)
		}
		// 容量超限：按 lastAccess 升序 LRU 驱逐
		var alive []*cacheEntry
		for _, e := range list {
			if _, dead := findEntry(inactive, e); !dead {
				alive = append(alive, e)
			}
		}
		sort.Slice(alive, func(i, j int) bool { return alive[i].lastAccess < alive[j].lastAccess })
		for _, e := range alive {
			if cacheBytes[siteId] <= policy[0] {
				break
			}
			cacheRemoveLocked(e)
		}
		if cacheBytes[siteId] < 0 {
			cacheBytes[siteId] = 0
		}
	}
}

func findEntry(list []*cacheEntry, e *cacheEntry) (int, bool) {
	for i, v := range list {
		if v == e {
			return i, true
		}
	}
	return -1, false
}

// cacheStatusView 状态视图：总占用、条目数、各站点命中/未命中
func cacheStatusView() *core.Row {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	m := core.NewRow()
	m.Set("totalBytes", cacheTotalBytesLocked())
	m.Set("entries", len(cacheIndex))
	siteIds := map[int64]bool{}
	for k := range cacheHits {
		siteIds[k] = true
	}
	for k := range cacheMisses {
		siteIds[k] = true
	}
	ids := make([]int64, 0, len(siteIds))
	for k := range siteIds {
		ids = append(ids, k)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] }) // TreeMap 升序语义
	perSite := make([]interface{}, 0, len(ids))
	for _, siteId := range ids {
		perSite = append(perSite, core.NewRow().
			Set("siteId", siteId).
			Set("hits", cacheHits[siteId]).
			Set("misses", cacheMisses[siteId]).
			Set("bytes", cacheBytes[siteId]))
	}
	m.Set("sites", perSite)
	return m
}

func cacheTotalBytesLocked() int64 {
	var sum int64
	for _, v := range cacheBytes {
		sum += v
	}
	return sum
}

// ---------- 内部 ----------

// cacheRemoveLocked 以索引移除为准：并发方已删则跳过，避免容量双扣与重复删文件（调用方持 cacheMu）
func cacheRemoveLocked(e *cacheEntry) {
	h := keyHash(e.key)
	if _, ok := cacheIndex[h]; !ok {
		return
	}
	delete(cacheIndex, h)
	cacheBytes[e.siteId] -= e.size
	deleteEntryFiles(e)
}

func deleteEntryFiles(e *cacheEntry) {
	if e == nil {
		return
	}
	deleteQuietly(e.file)
	deleteQuietly(siblingMeta(e.file))
}

func cacheDirFor(siteId int64, key string) string {
	hash := keyHash(key)
	return filepath.Join(cacheRoot(), strconv.FormatInt(siteId, 10), hash[0:2])
}

func keyHash(key string) string {
	d := sha256.Sum256([]byte(key))
	return hex.EncodeToString(d[:])
}

func deleteQuietly(p string) {
	if p == "" {
		return
	}
	_ = os.Remove(p)
}

func randHex16() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return strconv.FormatInt(nowMillis(), 16)
	}
	return hex.EncodeToString(b)
}

func stripSuffix(name string) string {
	i := strings.LastIndexByte(name, '.')
	if i > 0 {
		return name[:i]
	}
	return name
}

func siblingMeta(data string) string {
	return filepath.Join(filepath.Dir(data), stripSuffix(filepath.Base(data))+".meta")
}

// writeMeta 元数据落盘（键序与 Java JsonObject 一致：siteId,key,status,size,expiresAt,headers）
func writeMeta(e *cacheEntry) error {
	o := core.NewRow().
		Set("siteId", e.siteId).
		Set("key", e.key).
		Set("status", e.status).
		Set("size", e.size).
		Set("expiresAt", e.expiresAt)
	hs := make([]interface{}, 0, len(e.headers))
	for _, h := range e.headers {
		hs = append(hs, []interface{}{h[0], h[1]})
	}
	o.Set("headers", hs)
	b, err := core.MarshalJSON(o)
	if err != nil {
		return err
	}
	return os.WriteFile(siblingMeta(e.file), b, 0o644)
}

// readMeta 读取元数据；.data 缺失返回 nil（调用方清理）
func readMeta(metaPath string, siteId int64) (*cacheEntry, error) {
	b, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, err
	}
	var raw interface{}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return nil, err
	}
	o, ok := raw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("元数据不是 JSON 对象")
	}
	var headers [][2]string
	if el, isNull := objGet(o, "headers"); el != nil && !isNull {
		if arr, ok := el.([]interface{}); ok {
			for _, v := range arr {
				pair, ok := v.([]interface{})
				if !ok || len(pair) < 2 {
					continue
				}
				headers = append(headers, [2]string{strOf(pair[0]), strOf(pair[1])})
			}
		}
	}
	data := filepath.Join(filepath.Dir(metaPath), stripSuffix(filepath.Base(metaPath))+".data")
	if _, err := os.Stat(data); err != nil {
		return nil, nil
	}
	size := jsonInt64(o, "size", -1)
	if size < 0 {
		if st, err := os.Stat(data); err == nil {
			size = st.Size()
		} else {
			size = 0
		}
	}
	return &cacheEntry{
		siteId:     siteId,
		key:        strOf(o["key"]),
		file:       data,
		status:     int(jsonInt64(o, "status", 200)),
		headers:    headers,
		size:       size,
		expiresAt:  jsonInt64(o, "expiresAt", 0),
		lastAccess: nowMillis(),
	}, nil
}

func jsonInt64(o map[string]interface{}, key string, def int64) int64 {
	n, ok := o[key].(json.Number)
	if !ok {
		return def
	}
	v, err := n.Int64()
	if err != nil {
		f, ferr := n.Float64()
		if ferr != nil {
			return def
		}
		return int64(f)
	}
	return v
}

// extensionOf URL 的缓存扩展名（去查询串），无扩展名返回空串
func extensionOf(pathAndQuery string) string {
	path := pathAndQuery
	if q := strings.IndexByte(path, '?'); q >= 0 {
		path = path[:q]
	}
	dot := strings.LastIndexByte(path, '.')
	slash := strings.LastIndexByte(path, '/')
	if dot <= slash+1 {
		return ""
	}
	ext := path[dot+1:]
	if len(ext) > 10 {
		return ""
	}
	return strings.ToLower(ext)
}
