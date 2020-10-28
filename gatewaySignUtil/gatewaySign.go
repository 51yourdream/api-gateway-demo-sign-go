package gatewaySignUtil

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"gatewaySign/common"
	"sort"
	"strings"
)

//Sign	构建待签名
//path uri
//method 请求方式
//secret appSecret
//header
//querys http query 参数
//bodys post请求相关参数
//signHeaderPrefixList 需要参数加密的header key
func Sign(path, method, secret string, headers *map[string]interface{}, querys, bodys, signHeaderPrefixList map[string]interface{}) string {
	path = "/" + strings.Trim(path, "/")
	signStr := buildStringToSign(path, method, headers, querys, bodys, signHeaderPrefixList)
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(signStr))
	shaStr := base64.StdEncoding.EncodeToString(h.Sum(nil))

	return shaStr
}

//buildStringToSign		构建待签名path+(header+query+body)
func buildStringToSign(path, method string, headers *map[string]interface{}, querys, bodys, signHeaderPrefixList map[string]interface{}) string{
	sb := strings.ToUpper(method)
	sb += LF
	if value, ok := (*headers)[HTTP_HEADER_ACCEPT]; ok && len(common.Interface2Str(value)) > 0 {
		sb += common.Interface2Str(value)
	}else{
		sb += "*/*"
	}
	sb += LF

	if value, ok := (*headers)[HTTP_HEADER_CONTENT_MD5]; ok && len(common.Interface2Str(value)) > 0 {
		sb += common.Interface2Str(value)
	}
	sb += LF
	if value, ok := (*headers)[HTTP_HEADER_CONTENT_TYPE]; ok && len(common.Interface2Str(value)) > 0 {
		sb += common.Interface2Str(value)
	}
	sb += LF
	if value, ok := (*headers)[HTTP_HEADER_DATE]; ok && len(common.Interface2Str(value)) > 0 {
		sb += common.Interface2Str(value)
	}
	sb += LF
	sb += buildHeader(headers, signHeaderPrefixList)
	sb += buildResource(path, querys, bodys)
	return sb
}


//buildResource	构建待签名Path+Query+FormParams
func buildResource(path string, querys, bodys map[string]interface{}) string {
	var (
		sb, sbParam string
		sortMap map[string]interface{}
		sortKeyList []string
	)
	if len(path) > 0 {
		sb = path
	}
	sortMap = make(map[string]interface{})
	for key, value := range querys {
		if len(key) > 0 {
			sortMap[key] = value
			sortKeyList = append(sortKeyList, key)
		}
	}

	for key, value := range bodys {
		if len(key) > 0 {
			sortMap[key] = value
			sortKeyList = append(sortKeyList, key)
		}
	}

	sort.Strings(sortKeyList)

	for _, key := range sortKeyList {
		if len(sbParam) > 0{
			sbParam +="&";
		}
		sbParam += key
		if value, ok := sortMap[key]; ok {
			newValue := common.Interface2Str(value)
			if len(newValue) > 0 {
				sbParam += "="
				sbParam += newValue
			}
		}
	}

	if len(sbParam) > 0 {
		sb += "?"
		sb += sbParam
	}
	return sb
}

//buildHeader	构建待签名Http头
func buildHeader(headers *map[string]interface{}, signHeaderPrefixList map[string]interface{}) string {
	var headerKeyList []string
	sb := ""
	signHeadersStringBuilder := ""
	delete(signHeaderPrefixList, X_CA_SIGNATURE)
	delete(signHeaderPrefixList, HTTP_HEADER_ACCEPT)
	delete(signHeaderPrefixList, HTTP_HEADER_CONTENT_MD5)
	delete(signHeaderPrefixList, HTTP_HEADER_CONTENT_TYPE)
	delete(signHeaderPrefixList, HTTP_HEADER_DATE)
	for key, _ := range *headers {
		headerKeyList = append(headerKeyList, key)
	}
	//升序排序
	sort.Strings(headerKeyList)
	for _, key := range headerKeyList {
		value := common.Interface2Str((*headers)[key])
		if isHeaderToSign(key, signHeaderPrefixList) {
			sb += key
			sb += SPE2
			if len(value) > 0 {
				sb += value
			}
			sb += LF
			if len(signHeadersStringBuilder) > 0 {
				signHeadersStringBuilder += SPE1
			}
			signHeadersStringBuilder += key
		}
	}

	(*headers)[X_CA_SIGNATURE_HEADERS] = signHeadersStringBuilder

	return sb
}

//isHeaderToSign 判断是否需要参与签名
func isHeaderToSign(headerName string, signHeaderPrefixList map[string]interface{}) bool {
	if headerName == "" {
		return false
	}

	if strings.HasPrefix(headerName, CA_HEADER_TO_SIGN_PREFIX_SYSTEM) {
		return true
	}

	if _, ok := signHeaderPrefixList[headerName]; ok {
		return true
	}

	return false
}

