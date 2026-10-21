package core

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"
)

// JSON 请求体工具：等价复刻 JsonUtils 的字段读取语义，
// 使「GET 列表行 → 编辑 → PUT 回写」的布尔/数值往返不会被静默改变。

// MarshalJSON 序列化响应体：Row 通过自定义 Marshaler 保序输出，普通 map/切片由 encoding/json 处理。
func MarshalJSON(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

// ParseBody 解析 JSON 文本为对象；空/非法返回空对象（等价 JsonUtils.parse）。
func ParseBody(text string) map[string]interface{} {
	text = strings.TrimSpace(text)
	if text == "" {
		return map[string]interface{}{}
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(text), &m); err != nil || m == nil {
		return map[string]interface{}{}
	}
	return m
}

// BodyStr 取字符串字段，缺失/为 null 返回空串（等价 JsonUtils.str）。
func BodyStr(o map[string]interface{}, key string) string {
	v, ok := o[key]
	if !ok || v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case float64:
		return numToString(x)
	default:
		return ""
	}
}

// BodyNum 取整型字段，缺失/为 null/非法返回默认值（等价 JsonUtils.num）。
func BodyNum(o map[string]interface{}, key string, def int) int {
	v, ok := o[key]
	if !ok || v == nil {
		return def
	}
	switch x := v.(type) {
	case float64:
		return int(math.Round(x))
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(x)); err == nil {
			return n
		}
		return def
	default:
		return def
	}
}

// BodyBool 取布尔字段，缺失返回默认值。
// 兼容 SQLite 布尔列直出的整数/字符串形态（0/1），语义与 JsonUtils.bool 完全一致：
// 数值非 0 为 true；字符串 "true"/"false" 忽略大小写；其余按是否等于 "1" 判定。
func BodyBool(o map[string]interface{}, key string, def bool) bool {
	v, ok := o[key]
	if !ok || v == nil {
		return def
	}
	switch x := v.(type) {
	case bool:
		return x
	case float64:
		return x != 0
	case string:
		s := strings.TrimSpace(x)
		if strings.EqualFold(s, "true") {
			return true
		}
		if strings.EqualFold(s, "false") {
			return false
		}
		return s == "1"
	default:
		return def
	}
}

// numToString 将 JSON 数值转为字符串：整数值不带小数点（对齐 Gson getAsString 常见形态）。
func numToString(f float64) string {
	if f == math.Trunc(f) && math.Abs(f) < 1e15 {
		return strconv.FormatInt(int64(f), 10)
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}
