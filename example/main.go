package main

import (
	"fmt"
	"gatewaySign/gatewaySignUtil"
	"strconv"
	"time"
)

func main()  {
	headers := make(map[string]interface{})
	querys :=  make(map[string]interface{})
	bodys := make(map[string]interface{})
	signHeaderPrefixList := make(map[string]interface{})

	appKey := "appKey"
	path := "/user/add"
	appSecret := "appSecret"

	headers[gatewaySignUtil.X_CA_TIMESTAMP] = strconv.FormatInt(time.Now().Unix() * 1000, 10)
	headers[gatewaySignUtil.X_CA_NONCE] = "随机不重复字符串"
	headers[gatewaySignUtil.HTTP_HEADER_CONTENT_TYPE] = "application/json"
	headers[gatewaySignUtil.HTTP_HEADER_ACCEPT] = "*/*"
	headers[gatewaySignUtil.X_CA_KEY] = appKey
	headers[gatewaySignUtil.X_Ca_Stage] = "RELEASE"
	sign := gatewaySignUtil.Sign(path, "POST", appSecret, &headers, querys, bodys, signHeaderPrefixList)
	headers[gatewaySignUtil.X_CA_SIGNATURE] = sign
	fmt.Printf("headers:%v \n", headers)
	fmt.Printf("sign:%v \n", sign)
}
