package ddns

import "errors"

// 对外导出的阿里云接口包装（等价 Java AliyunClient 的 public static 语义）：
// 证书模块（DNS01 自动写入 _acme-challenge TXT）与后续 STUN 模块（ESA 记录/回源规则）跨包复用。
// 实现与内部私有函数完全一致，仅暴露命名，行为无任何分支。

// DnsDescribeRecords 查询域名下指定主机记录的解析列表。
func DnsDescribeRecords(ak, sk, domain, rr string) ([]map[string]interface{}, error) {
	return dnsDescribeRecords(ak, sk, domain, rr)
}

// DnsAddRecord 新增云解析记录，返回 RecordId。
func DnsAddRecord(ak, sk, domain, rr, typ, value string, ttl int) (string, error) {
	return dnsAddRecord(ak, sk, domain, rr, typ, value, ttl)
}

// DnsDeleteRecord 删除云解析记录。
func DnsDeleteRecord(ak, sk, recordId string) error {
	return dnsDeleteRecord(ak, sk, recordId)
}

// EsaListRecords 查询 ESA 站点下指定记录名的解析列表。
func EsaListRecords(ak, sk, siteId, recordName string) ([]map[string]interface{}, error) {
	return esaListRecords(ak, sk, siteId, recordName)
}

// EsaCreateRecord 新增 ESA 解析记录，返回 RecordId。
func EsaCreateRecord(ak, sk, siteId, recordName, typ, value string, ttl int) (string, error) {
	return esaCreateRecord(ak, sk, siteId, recordName, typ, value, ttl)
}

// EsaDeleteRecord 删除 ESA 解析记录。
func EsaDeleteRecord(ak, sk, recordId string) error {
	return esaDeleteRecord(ak, sk, recordId)
}

// EsaListSites 拉取 ESA 站点列表（STUN 任务表单下拉选择，不手填 SiteId）。
func EsaListSites(ak, sk string) ([]map[string]interface{}, error) {
	return esaListSites(ak, sk)
}

// EsaListAllRecords 查询 ESA 站点下全部解析记录（含 RecordId/RecordName/Data.Value 等线上字段）。
func EsaListAllRecords(ak, sk, siteId string) ([]map[string]interface{}, error) {
	return esaListAllRecords(ak, sk, siteId)
}

// EsaListOriginRules 查询 ESA 站点下全部回源规则（含 ConfigId/RuleName/OriginScheme/OriginHttpsPort）。
func EsaListOriginRules(ak, sk, siteId string) ([]map[string]interface{}, error) {
	return esaListOriginRules(ak, sk, siteId)
}

// EsaUpdateRecordValue 更新 ESA 解析记录值（线上 Type/Ttl/Proxied 原样回传，只改 Data.Value）。
func EsaUpdateRecordValue(ak, sk, recordId, typ, value string, ttl int, proxied bool) error {
	return esaUpdateRecordValue(ak, sk, recordId, typ, value, ttl, proxied)
}

// EsaUpdateOriginRulePort 更新 ESA 回源规则的 HTTPS 回源端口（OriginScheme 沿用规则现值）。
func EsaUpdateOriginRulePort(ak, sk, siteId, configId, originScheme, httpsPort string) error {
	return esaUpdateOriginRulePort(ak, sk, siteId, configId, originScheme, httpsPort)
}

// APIErrorCode 提取错误中的阿里云错误码（非 APIError 返回空串），供跨包做 NotFound 判定。
func APIErrorCode(err error) string {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.Code
	}
	return ""
}
