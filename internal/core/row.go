package core

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Row 是一个保持列插入顺序的 JSON 对象，用于等价复刻 Java 侧 LinkedHashMap + Gson 的序列化行为：
//   - 键顺序 = 插入顺序（数据库列名顺序 / 手动 Put 顺序），而 map 会被 encoding/json 按字典序重排；
//   - nil 值输出为 JSON null（等价 Gson serializeNulls），不得省略字段。
//
// 前端多数按 key 取值，但存在通用遍历列的表格/明细渲染，保序可最大化行为一致、降低回归风险。
type Row struct {
	keys []string
	m    map[string]interface{}
}

func NewRow() *Row {
	return &Row{m: map[string]interface{}{}}
}

// Set 写入字段；nil 值会保留并在 JSON 中输出为 null。
func (r *Row) Set(key string, val interface{}) *Row {
	if _, ok := r.m[key]; !ok {
		r.keys = append(r.keys, key)
	}
	r.m[key] = val
	return r
}

// Get 读取字段值（不存在返回 nil）。
func (r *Row) Get(key string) interface{} { return r.m[key] }

// Has 是否存在该键。
func (r *Row) Has(key string) bool {
	_, ok := r.m[key]
	return ok
}

// Keys 返回插入顺序的键列表。
func (r *Row) Keys() []string { return r.keys }

// MarshalJSON 按插入顺序输出对象；键经 json 编码，值用 encoding/json（nil→null）。
func (r *Row) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range r.keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		buf.Write(kb)
		buf.WriteByte(':')
		vb, err := json.Marshal(r.m[k])
		if err != nil {
			return nil, fmt.Errorf("字段 %q 序列化失败: %w", k, err)
		}
		buf.Write(vb)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// Rows 是 Row 切片，供列表接口直接作为 data 返回（[]*Row 亦可被 json 正确序列化）。
type Rows = []*Row

// RowList 是可变长的 Row 列表，用于需要「空也输出 []（而非 null）」的响应字段（等价 Java 的 List）。
// 通过自定义 Marshaler 保证 nil/空切片均编码为 JSON 空数组，与 Gson 行为一致。
type RowList struct {
	items []*Row
}

func NewRowList() *RowList { return &RowList{items: []*Row{}} }

// Append 追加一行，返回自身便于链式调用。
func (l *RowList) Append(r *Row) *RowList {
	l.items = append(l.items, r)
	return l
}

// Items 返回底层切片。
func (l *RowList) Items() []*Row { return l.items }

// Len 元素个数。
func (l *RowList) Len() int { return len(l.items) }

// MarshalJSON 空列表编码为 []，非空逐元素编码。
func (l *RowList) MarshalJSON() ([]byte, error) {
	if len(l.items) == 0 {
		return []byte("[]"), nil
	}
	return json.Marshal(l.items)
}
