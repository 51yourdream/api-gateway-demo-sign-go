package gatewaySignUtil

const (
	CA_HEADER_TO_SIGN_PREFIX_SYSTEM = "X-Ca-"
	LF = "\n"
	SPE1 = ","
	SPE2 = ":"
)

// HTTP头常量
const (

	HTTP_HEADER_ACCEPT = "Accept" //请求Header Accept
	HTTP_HEADER_CONTENT_MD5 = "Content-MD5" //请求Body内容MD5 Header
	HTTP_HEADER_CONTENT_TYPE = "Content-Type" //请求Header Content-Type
	HTTP_HEADER_USER_AGENT = "User-Agent"  //请求Header UserAgent
	HTTP_HEADER_DATE = "Date" //请求Header Date
)

// 系统HTTP头常量
const (
	//签名Header
	X_CA_SIGNATURE = "X-Ca-Signature"
	//所有参与签名的Header
	X_CA_SIGNATURE_HEADERS = "X-Ca-Signature-Headers"
	//请求时间戳
	X_CA_TIMESTAMP = "X-Ca-Timestamp"
	//请求放重放Nonce,15分钟内保持唯一,建议使用UUID
	X_CA_NONCE = "X-Ca-Nonce"
	//APP KEY
	X_CA_KEY = "X-Ca-Key"
	X_Ca_Stage = "X-Ca-Stage"
)