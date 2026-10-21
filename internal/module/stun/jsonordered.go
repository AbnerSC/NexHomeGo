package stun

// JSON 顺序解析辅助：Go 的 encoding/json 解码对象到 map 会丢失键序，而本模块的
// webhook 推送顺序（headers/params → GET 查询串/默认 POST 体）、webhook_status/esa_sync_status
// 的回写都需要保持配置/历史数据的原始键序（Java LinkedHashMap + Gson 语义）。
// json.Decoder 逐 token 解析可恢复对象键的文本顺序。

import (
	"encoding/json"
	"strconv"
	"strings"
)

type jsonEntry struct {
	key   string
	value json.RawMessage
}

// orderedJSONEntries 按文本顺序解析 JSON 对象的键值对；非对象/非法返回 nil。
// 值保留原始 JSON 文本（RawMessage），重新序列化时字节不变，便于原样回写。
func orderedJSONEntries(text string) []jsonEntry {
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '{' {
		return nil
	}
	var out []jsonEntry
	for dec.More() {
		kt, err := dec.Token() // 键
		if err != nil {
			break
		}
		key, _ := kt.(string)
		var raw json.RawMessage // 值（保留原始文本）
		if err := dec.Decode(&raw); err != nil {
			break
		}
		out = append(out, jsonEntry{key: key, value: raw})
	}
	return out
}

// rawStr 从 map[string]json.RawMessage 取字符串字段（缺失/null/非字符串返回空串，等价 JsonUtils.str）
func rawStr(o map[string]json.RawMessage, key string) string {
	raw, ok := o[key]
	if !ok {
		return ""
	}
	if s, ok2 := jsonStr(raw); ok2 {
		return s
	}
	return ""
}

// jsonStr 若原始值是 JSON 字符串则解码返回（等价 Gson getAsString 对字符串项的语义）
func jsonStr(raw json.RawMessage) (string, bool) {
	trimmed := string(raw)
	if len(trimmed) == 0 || trimmed[0] != '"' {
		return "", false
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

// rawLong 从 map[string]json.RawMessage 取整型字段（数字/数字字符串，缺失/非法返回 0）
func rawLong(o map[string]json.RawMessage, key string) int64 {
	raw, ok := o[key]
	if !ok || string(raw) == "null" {
		return 0
	}
	var n json.Number
	if json.Unmarshal(raw, &n) == nil {
		if v, err := n.Int64(); err == nil {
			return v
		}
		if f, err := n.Float64(); err == nil {
			return int64(f)
		}
		return 0
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		if v, err := strconv.ParseInt(trimStr(s), 10, 64); err == nil {
			return v
		}
		if f, err := strconv.ParseFloat(trimStr(s), 64); err == nil {
			return int64(f)
		}
	}
	return 0
}

func trimStr(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t' || s[0] == '\n' || s[0] == '\r') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t' || s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
