package ddns

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"NexHomeGo/internal/core"
)

// 阿里云 OpenAPI 轻量客户端（不依赖官方 SDK，避免引入重型依赖，逐函数复刻 Java AliyunClient）。
// 支持两套接口与签名算法：
//   - 云解析 DNS（alidns.aliyuncs.com，Version=2015-01-09）：RPC 风格 + 签名算法 1.0（HMAC-SHA1）
//   - 边缘安全加速 ESA（esa.cn-hangzhou.aliyuncs.com，Version=2024-09-10）：签名算法 3.0（ACS3-HMAC-SHA256）
//
// AccessKey 配置位置：每个 DDNS 任务中单独填写（存于 SQLite ddns_task 表），
// 或引用服务商凭证配置（provider.Credentials 实时读取）。

const isoZLayout = "2006-01-02T15:04:05Z" // x-acs-date 必须无小数秒，带纳秒会被阿里云拒绝（InvalidTimeStamp.Format）

// 接口端点（生产不赋值；声明为变量仅作单测 httptest 注入点）
var (
	dnsHost   = "https://alidns.aliyuncs.com/"
	esaScheme = "https"
	esaHost   = "esa.cn-hangzhou.aliyuncs.com"
)

var aliyunHTTP = &http.Client{
	Transport: &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true, // Java HttpClient 默认 h2，阿里云官方网关支持
		MaxIdleConns:          16,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	},
}

// APIError 阿里云 OpenAPI 业务错误（携带错误码），由 HTTP 非 200 响应解析而来。
// 替代原始错误报文使任务失败状态中的错误信息（错误码 + 描述）更易读，
// 上层依据 Code 是否含 NotFound 做「记录已不存在」降级（等价 Java AliyunApiException）。
type APIError struct {
	Code string
	Msg  string
}

func (e *APIError) Error() string { return "阿里云API错误[" + e.Code + "]: " + e.Msg }

// isNotFound 错误码是否含 NotFound（如 InvalidDomainRecordNotFound /NoSuchRecord）。
func (e *APIError) isNotFound() bool { return strings.Contains(e.Code, "NotFound") }

// ==================== 云解析 DNS（签名 1.0） ====================

// dnsDescribeRecords 查询域名下指定主机记录的解析列表（响应结构 DomainRecords.Record，无匹配缺省为空）。
func dnsDescribeRecords(ak, sk, domain, rr string) ([]map[string]interface{}, error) {
	resp, err := dnsCall(ak, sk, map[string]string{
		"Action":     "DescribeDomainRecords",
		"DomainName": domain,
		"PageSize":   "100",
		"RRKeyWord":  rr,
	})
	if err != nil {
		return nil, err
	}
	if err := checkDnsError(resp); err != nil {
		return nil, err
	}
	// 响应结构为 DomainRecords.Record，无匹配时该节点可能缺省
	records := objAt(resp, "DomainRecords")
	if records == nil {
		return nil, nil
	}
	return arrAt(records, "Record"), nil
}

// dnsAddRecord 新增解析记录，返回 RecordId。
func dnsAddRecord(ak, sk, domain, rr, typ, value string, ttl int) (string, error) {
	resp, err := dnsCall(ak, sk, map[string]string{
		"Action":     "AddDomainRecord",
		"DomainName": domain,
		"RR":         rr,
		"Type":       typ,
		"Value":      value,
		"TTL":        strconv.Itoa(ttl),
	})
	if err != nil {
		return "", err
	}
	if err := checkDnsError(resp); err != nil {
		return "", err
	}
	return strAt(resp, "RecordId"), nil
}

// dnsUpdateRecord 更新解析记录。
func dnsUpdateRecord(ak, sk, recordId, rr, typ, value string, ttl int) error {
	resp, err := dnsCall(ak, sk, map[string]string{
		"Action":   "UpdateDomainRecord",
		"RecordId": recordId,
		"RR":       rr,
		"Type":     typ,
		"Value":    value,
		"TTL":      strconv.Itoa(ttl),
	})
	if err != nil {
		return err
	}
	return checkDnsError(resp)
}

// dnsDeleteRecord 删除解析记录（云解析 DNS）。
func dnsDeleteRecord(ak, sk, recordId string) error {
	resp, err := dnsCall(ak, sk, map[string]string{
		"Action":   "DeleteDomainRecord",
		"RecordId": recordId,
	})
	if err != nil {
		return err
	}
	return checkDnsError(resp)
}

// checkDnsError 响应体带 Code 字段即为业务错误（等价 Java checkDnsError）。
func checkDnsError(resp map[string]interface{}) error {
	if v, ok := resp["Code"]; ok && v != nil {
		return fmt.Errorf("阿里云DNS错误[%s]: %s", strAt(resp, "Code"), strAtIfPresent(resp, "Message"))
	}
	return nil
}

// dnsCall 云解析 RPC 调用：组装公共参数并按签名算法 1.0 签名（HMAC-SHA1 + Base64）。
func dnsCall(ak, sk string, biz map[string]string) (map[string]interface{}, error) {
	params := make(map[string]string, len(biz)+7)
	for k, v := range biz {
		params[k] = v
	}
	params["Format"] = "JSON"
	params["Version"] = "2015-01-09"
	params["AccessKeyId"] = ak
	params["SignatureMethod"] = "HMAC-SHA1"
	params["SignatureVersion"] = "1.0"
	params["SignatureNonce"] = newUUID()
	params["Timestamp"] = time.Now().UTC().Format(isoZLayout)

	// 1) 构造规范化查询串（按参数名排序；参数名均为 ASCII，字典序与 Java TreeMap 一致）
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var canonical strings.Builder
	for i, k := range keys {
		if i > 0 {
			canonical.WriteByte('&')
		}
		canonical.WriteString(percentEncode(k))
		canonical.WriteByte('=')
		canonical.WriteString(percentEncode(params[k]))
	}

	// 2) 构造待签名字符串：HTTPMethod&%2F&percentEncode(canonical)
	stringToSign := "GET&" + percentEncode("/") + "&" + percentEncode(canonical.String())

	// 3) HMAC-SHA1 签名（密钥为 AccessKeySecret + "&"）
	mac := hmac.New(sha1.New, []byte(sk+"&"))
	mac.Write([]byte(stringToSign))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	rawURL := dnsHost + "?Signature=" + percentEncode(signature) + "&" + canonical.String()
	return httpJSON("GET", rawURL, nil)
}

// ==================== ESA 边缘安全加速（签名 3.0） ====================

// esaListRecords 查询站点下指定记录名的解析列表。
func esaListRecords(ak, sk, siteId, recordName string) ([]map[string]interface{}, error) {
	resp, err := esaCall(ak, sk, "GET", "ListRecords", map[string]string{
		"SiteId":     siteId,
		"RecordName": recordName,
	})
	if err != nil {
		return nil, err
	}
	return arrAt(resp, "Records"), nil
}

// esaListSites 查询账号下全部 ESA 站点（自动分页），元素含 SiteId / SiteName / Status。
// 用于创建 ESA 任务时校验站点是否存在、供前端下拉选择。
func esaListSites(ak, sk string) ([]map[string]interface{}, error) {
	var all []map[string]interface{}
	page := 1
	const pageSize = 100
	for page <= 50 { // 安全上限，避免异常分页导致死循环
		resp, err := esaCall(ak, sk, "GET", "ListSites", map[string]string{
			"PageNumber": strconv.Itoa(page),
			"PageSize":   strconv.Itoa(pageSize),
		})
		if err != nil {
			return nil, err
		}
		if err := checkEsaError(resp); err != nil {
			return nil, err
		}
		sites := arrAt(resp, "Sites")
		all = append(all, sites...)
		total := len(all)
		if v, ok := numAt(resp, "TotalCount"); ok {
			total = int(v)
		}
		if len(sites) == 0 || len(all) >= total {
			break
		}
		page++
	}
	return all, nil
}

// esaCreateRecord 新增 ESA 解析记录，返回 RecordId。
func esaCreateRecord(ak, sk, siteId, recordName, typ, value string, ttl int) (string, error) {
	resp, err := esaCall(ak, sk, "POST", "CreateRecord", map[string]string{
		"SiteId":     siteId,
		"RecordName": recordName,
		"Type":       esaRecordType(typ),
		"Data":       esaDataJSON(value),
		"Ttl":        strconv.Itoa(ttl),
	})
	if err != nil {
		return "", err
	}
	if err := checkEsaError(resp); err != nil {
		return "", err
	}
	return strAt(resp, "RecordId"), nil
}

// esaUpdateRecord 更新 ESA 解析记录。
func esaUpdateRecord(ak, sk, recordId, typ, value string, ttl int) error {
	resp, err := esaCall(ak, sk, "POST", "UpdateRecord", map[string]string{
		"RecordId": recordId,
		"Type":     esaRecordType(typ),
		"Data":     esaDataJSON(value),
		"Ttl":      strconv.Itoa(ttl),
	})
	if err != nil {
		return err
	}
	return checkEsaError(resp)
}

// esaRecordType ESA 地址类记录的类型枚举为合并的 "A/AAAA"（与云解析 DNS 的 A/AAAA 不同）。
func esaRecordType(typ string) string {
	if strings.EqualFold(typ, "A") || strings.EqualFold(typ, "AAAA") {
		return "A/AAAA"
	}
	return typ
}

// esaDataJSON ESA 的 Data 为复合对象参数，需以 JSON 字符串传递，如 {"Value":"1.2.3.4"}。
func esaDataJSON(value string) string {
	r := core.NewRow()
	r.Set("Value", value)
	b, _ := json.Marshal(r)
	return string(b)
}

// esaDeleteRecord 删除 ESA 解析记录。
func esaDeleteRecord(ak, sk, recordId string) error {
	resp, err := esaCall(ak, sk, "POST", "DeleteRecord", map[string]string{
		"RecordId": recordId,
	})
	if err != nil {
		return err
	}
	return checkEsaError(resp)
}

// esaListAllRecords 查询站点下全部解析记录（自动分页）。
// 不按 RecordName 过滤：通配记录（如 *.edge.example.com）的精确名查询并不可靠，
// 统一拉全量后由调用方本地匹配，顺带拿到线上 Type/Ttl/Proxied 以便原样回传。
func esaListAllRecords(ak, sk, siteId string) ([]map[string]interface{}, error) {
	var all []map[string]interface{}
	page := 1
	for page <= 50 { // 安全上限，避免异常分页导致死循环
		resp, err := esaCall(ak, sk, "GET", "ListRecords", map[string]string{
			"SiteId":     siteId,
			"PageNumber": strconv.Itoa(page),
			"PageSize":   "500",
		})
		if err != nil {
			return nil, err
		}
		if err := checkEsaError(resp); err != nil {
			return nil, err
		}
		records := arrAt(resp, "Records")
		all = append(all, records...)
		total := len(all)
		if v, ok := numAt(resp, "TotalCount"); ok {
			total = int(v)
		}
		if len(records) == 0 || len(all) >= total {
			break
		}
		page++
	}
	return all, nil
}

// esaListOriginRules 查询站点下全部回源规则（自动分页）。
// 元素含 ConfigId / RuleName / ConfigType(global|rule) / OriginScheme / OriginHttpsPort 等。
func esaListOriginRules(ak, sk, siteId string) ([]map[string]interface{}, error) {
	var all []map[string]interface{}
	page := 1
	for page <= 50 {
		resp, err := esaCall(ak, sk, "GET", "ListOriginRules", map[string]string{
			"SiteId":     siteId,
			"PageNumber": strconv.Itoa(page),
			"PageSize":   "500",
		})
		if err != nil {
			return nil, err
		}
		if err := checkEsaError(resp); err != nil {
			return nil, err
		}
		configs := arrAt(resp, "Configs")
		all = append(all, configs...)
		total := len(all)
		if v, ok := numAt(resp, "TotalCount"); ok {
			total = int(v)
		}
		if len(configs) == 0 || len(all) >= total {
			break
		}
		page++
	}
	return all, nil
}

// esaUpdateRecordValue 更新 ESA 解析记录的记录值：Type / Ttl / Proxied 一律按线上现值原样回传，
// 避免只改记录值却把 TTL 或代理加速状态重置为默认值（供 STUN 模块后续复用）。
func esaUpdateRecordValue(ak, sk, recordId, typ, value string, ttl int, proxied bool) error {
	resp, err := esaCall(ak, sk, "POST", "UpdateRecord", map[string]string{
		"RecordId": recordId,
		"Type":     esaRecordType(typ),
		"Data":     esaDataJSON(value),
		"Ttl":      strconv.Itoa(ttl),
		"Proxied":  strconv.FormatBool(proxied),
	})
	if err != nil {
		return err
	}
	return checkEsaError(resp)
}

// esaUpdateOriginRulePort 更新 ESA 回源规则的回源 HTTPS 端口：OriginScheme 沿用线上规则现值
// （该接口为整体提交，漏传协议会被改回默认值），其余可选参数不传保持原配置（供 STUN 模块后续复用）。
func esaUpdateOriginRulePort(ak, sk, siteId, configId, originScheme, httpsPort string) error {
	resp, err := esaCall(ak, sk, "POST", "UpdateOriginRule", map[string]string{
		"SiteId":          siteId,
		"ConfigId":        configId,
		"OriginScheme":    originScheme,
		"OriginHttpsPort": httpsPort,
	})
	if err != nil {
		return err
	}
	return checkEsaError(resp)
}

// checkEsaError ESA 响应带非空 Code 即为业务错误。
func checkEsaError(resp map[string]interface{}) error {
	if v, ok := resp["Code"]; ok && v != nil {
		if c := strAt(resp, "Code"); c != "" {
			return fmt.Errorf("阿里云ESA错误[%s]: %s", c, strAtIfPresent(resp, "Message"))
		}
	}
	return nil
}

// esaCall ESA API 调用：签名算法 3.0（ACS3-HMAC-SHA256）。
// 流程：构造规范请求 -> SHA256 摘要 -> HMAC-SHA256 签名 -> Authorization 头。
func esaCall(ak, sk, method, action string, params map[string]string) (map[string]interface{}, error) {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// 规范化查询串（参数名排序，URL 编码）
	var query strings.Builder
	for i, k := range keys {
		if i > 0 {
			query.WriteByte('&')
		}
		query.WriteString(rfcEncode(k))
		query.WriteByte('=')
		query.WriteString(rfcEncode(params[k]))
	}

	date := time.Now().UTC().Format(isoZLayout)
	nonce := newUUID()
	hashedEmptyBody := sha256Hex("")

	// 参与签名的头（按名称排序）
	canonicalHeaders := "host:" + esaHost + "\n" +
		"x-acs-action:" + action + "\n" +
		"x-acs-content-sha256:" + hashedEmptyBody + "\n" +
		"x-acs-date:" + date + "\n" +
		"x-acs-signature-nonce:" + nonce + "\n" +
		"x-acs-version:2024-09-10\n"
	signedHeaders := "host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version"

	// 规范请求（第一行 HTTPMethod 必须与实际请求方法一致，否则签名校验失败）
	canonicalRequest := method + "\n/\n" + query.String() + "\n" + canonicalHeaders + "\n" + signedHeaders + "\n" + hashedEmptyBody
	// 待签名字符串
	stringToSign := "ACS3-HMAC-SHA256\n" + sha256Hex(canonicalRequest)
	// 计算签名
	mac := hmac.New(sha256.New, []byte(sk))
	mac.Write([]byte(stringToSign))
	signature := hex.EncodeToString(mac.Sum(nil))

	authorization := "ACS3-HMAC-SHA256 Credential=" + ak +
		",SignedHeaders=" + signedHeaders + ",Signature=" + signature

	rawURL := esaScheme + "://" + esaHost + "/?" + query.String()
	return httpJSON(method, rawURL, map[string]string{
		"x-acs-action":          action,
		"x-acs-version":         "2024-09-10",
		"x-acs-date":            date,
		"x-acs-signature-nonce": nonce,
		"x-acs-content-sha256":  hashedEmptyBody,
		"Authorization":         authorization,
	})
}

// ==================== 底层工具 ====================

func httpJSON(method, rawURL string, headers map[string]string) (map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := aliyunHTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, apiError(resp.StatusCode, string(body))
	}
	// UseNumber：数字保留原始字面量（json.Number），等价 Gson 的精确数值承载——
	// ESA RecordId/ConfigId/SiteId 可达 18 位，float64 在 2^53 以上会丢精度（更新写回错误 id）
	var out map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("阿里云响应不是合法 JSON 对象: %s", err.Error())
	}
	return out, nil
}

// apiError 非 200 响应转业务异常：尽量解析错误码（如 DomainRecordDuplicate），供上层做已存在降级。
func apiError(status int, body string) error {
	var err map[string]interface{}
	if json.Unmarshal([]byte(body), &err) == nil {
		if v, ok := err["Code"]; ok && v != nil {
			msg := body
			if mv, ok := err["Message"]; ok && mv != nil {
				msg = strAt(err, "Message")
			}
			return &APIError{Code: strAt(err, "Code"), Msg: msg}
		}
	}
	return fmt.Errorf("HTTP %d: %s", status, body)
}

// percentEncode 阿里云签名 1.0 专用编码：URL 编码后修正 + * ~ 三个字符。
// Go url.QueryEscape 与 Java URLEncoder 的差异已在实现处对齐：空格→%20、*→%2A、~ 保持字面量。
func percentEncode(v string) string {
	s := url.QueryEscape(v)
	s = strings.ReplaceAll(s, "+", "%20")
	s = strings.ReplaceAll(s, "*", "%2A")
	s = strings.ReplaceAll(s, "%7E", "~")
	return s
}

// rfcEncode RFC3986 编码（签名 3.0 使用）。
func rfcEncode(v string) string {
	return strings.ReplaceAll(url.QueryEscape(v), "+", "%20")
}

func sha256Hex(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

// newUUID 随机 UUID v4（等价 Java UUID.randomUUID，作为 SignatureNonce/x-acs-signature-nonce）。
func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// ---------- 响应 JSON 取值工具（等价 Gson JsonObject 访问） ----------

func strAt(m map[string]interface{}, k string) string {
	v, ok := m[k]
	if !ok || v == nil {
		return ""
	}
	return jsonValueToString(v)
}

// strAtIfPresent 仅当键存在时取值；缺失返回空串（等价 Java has(k)?getAsString():""）。
func strAtIfPresent(m map[string]interface{}, k string) string {
	if _, ok := m[k]; !ok {
		return ""
	}
	return strAt(m, k)
}

// numAt 数值取值（UseNumber 下为 json.Number，测试构造可为 float64），键缺失/非数值返回 ok=false。
func numAt(m map[string]interface{}, k string) (float64, bool) {
	v, ok := m[k]
	if !ok || v == nil {
		return 0, false
	}
	switch x := v.(type) {
	case json.Number:
		f, err := x.Float64()
		return f, err == nil
	case float64:
		return x, true
	}
	return 0, false
}

func arrAt(m map[string]interface{}, k string) []map[string]interface{} {
	v, ok := m[k]
	if !ok || v == nil {
		return nil
	}
	list, _ := v.([]interface{})
	out := make([]map[string]interface{}, 0, len(list))
	for _, el := range list {
		if o, ok := el.(map[string]interface{}); ok {
			out = append(out, o)
		}
	}
	return out
}

func objAt(m map[string]interface{}, k string) map[string]interface{} {
	v, _ := m[k].(map[string]interface{})
	return v
}

// jsonValueToString 数值转字符串不带小数点（对齐 Gson getAsString 常见形态，如 SiteId/RecordId）。
func jsonValueToString(v interface{}) string {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return x.String() // 原始字面量精确无损（整数不带小数点，对齐 Gson getAsString）
	case float64:
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'g', -1, 64)
	case bool:
		if x {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}
