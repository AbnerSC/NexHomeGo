package docker

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// 有序 JSON 解析：等价复刻 Gson JsonElement 树的行为——
//   - 对象成员保持原文顺序（Networks/Ports 等需按 Daemon 返回顺序遍历）；
//   - 数值以 json.Number 保留原始字面量（对齐 Java getAsLong，避免 float64 精度损失）。

type jobj struct {
	keys []string
	m    map[string]interface{}
}

func newJObj() *jobj { return &jobj{m: map[string]interface{}{}} }

func (o *jobj) put(k string, v interface{}) {
	if _, ok := o.m[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.m[k] = v
}

// get 取原始值（缺失/JSON null 均返回 nil，与 Gson isJsonNull 语义一致）。
func (o *jobj) get(k string) interface{} {
	if o == nil {
		return nil
	}
	return o.m[k]
}

// str 等价 JsonUtils.str：缺失/null→""；布尔→"true"/"false"；数值→原始字面量。
func (o *jobj) str(k string) string {
	switch x := o.get(k).(type) {
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case json.Number:
		return x.String()
	}
	return ""
}

// long 等价 optLong：缺失/null/非法→0；小数按 getAsLong 截断取整。
func (o *jobj) long(k string) int64 {
	n, ok := o.get(k).(json.Number)
	if !ok {
		return 0
	}
	if v, err := n.Int64(); err == nil {
		return v
	}
	if f, err := n.Float64(); err == nil {
		return int64(f)
	}
	return 0
}

// dbl 取 double 字段（缺失→0），等价 getAsDouble。
func (o *jobj) dbl(k string) float64 {
	n, ok := o.get(k).(json.Number)
	if !ok {
		return 0
	}
	f, err := n.Float64()
	if err != nil {
		return 0
	}
	return f
}

// boolean 等价 JsonUtils.bool（仅原生布尔有意义，Docker API 返回真布尔值）。
func (o *jobj) boolean(k string, def bool) bool {
	if b, ok := o.get(k).(bool); ok {
		return b
	}
	return def
}

// arr 等价 optArray：非数组→空数组。
func (o *jobj) arr(k string) []interface{} {
	if a, ok := o.get(k).([]interface{}); ok {
		return a
	}
	return []interface{}{}
}

// obj 等价 optObj：非对象→空对象（永不返回 nil）。
func (o *jobj) obj(k string) *jobj {
	if x, ok := o.get(k).(*jobj); ok {
		return x
	}
	return newJObj()
}

// hasNonNull 等价 p.has(key) && !p.get(key).isJsonNull()。
func (o *jobj) hasNonNull(k string) bool {
	if o == nil {
		return false
	}
	v, ok := o.m[k]
	return ok && v != nil
}

// asObj 数组元素转对象（非对象→空对象，等价 el.getAsJsonObject 的常见用法）。
func asObj(v interface{}) *jobj {
	if x, ok := v.(*jobj); ok {
		return x
	}
	return newJObj()
}

// asStr 数组元素转字符串（等价 el.getAsString）。
func asStr(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	if n, ok := v.(json.Number); ok {
		return n.String()
	}
	return ""
}

// parseJSON 解析 JSON 文本为有序树；顶层非对象/数组时报错（等价 JsonParser.parseString 后续强转失败）。
func parseJSON(text string) (*jobj, error) {
	v, err := decodeValue(strings.NewReader(text))
	if err != nil {
		return nil, err
	}
	o, ok := v.(*jobj)
	if !ok {
		return nil, fmt.Errorf("JSON 响应格式异常（非对象）")
	}
	return o, nil
}

// parseJSONArray 顶层解析为数组。
func parseJSONArray(text string) ([]interface{}, error) {
	v, err := decodeValue(strings.NewReader(text))
	if err != nil {
		return nil, err
	}
	a, ok := v.([]interface{})
	if !ok {
		return nil, fmt.Errorf("JSON 响应格式异常（非数组）")
	}
	return a, nil
}

func decodeValue(r *strings.Reader) (interface{}, error) {
	dec := json.NewDecoder(r)
	dec.UseNumber()
	return decodeToken(dec)
}

func decodeToken(dec *json.Decoder) (interface{}, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return tok, nil // string / json.Number / bool / nil
	}
	switch d {
	case '{':
		o := newJObj()
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return nil, err
			}
			key, _ := kt.(string)
			val, err := decodeToken(dec)
			if err != nil {
				return nil, err
			}
			o.put(key, val)
		}
		_, _ = dec.Token() // 消耗 '}'
		return o, nil
	case '[':
		arr := []interface{}{}
		for dec.More() {
			val, err := decodeToken(dec)
			if err != nil {
				return nil, err
			}
			arr = append(arr, val)
		}
		_, _ = dec.Token() // 消耗 ']'
		return arr, nil
	}
	return nil, fmt.Errorf("JSON 格式异常")
}

// fmtDouble 输出与 Gson Double 序列化一致的数值：整值补 ".0"（如 12.0），小数保持原样。
func fmtDouble(v float64) json.Number {
	s := strconv.FormatFloat(v, 'f', -1, 64)
	if !strings.ContainsAny(s, ".eE") {
		s += ".0"
	}
	return json.Number(s)
}
