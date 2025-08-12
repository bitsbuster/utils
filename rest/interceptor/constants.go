package interceptor

const (
	AUTHORIZATION               string = "Authorization"
	HEADER_USER_NAME            string = "User-Name"
	HEADER_CUSTOMER_ID          string = "Customer-Id"
	HEADER_USER_ID              string = "User-Id"
	HEADER_SERVICE_ID           string = "Service-Id"
	HEADER_INPUT_APP            string = "x-application-vkn"
	HEADER_APP_ID               string = "App-Id"
	HEADER_REMOTE_IP            string = "Remote-Ip"
	HEADER_REQUEST_WEIGHT_NAME  string = "x-application-rw"
	HEADER_REQUEST_WEIGHT_VALUE string = "x-application-rv"
	HEADER_TIMESTAMP            string = "x-application-alo"
	HEADER_PLAN_ID              string = "Plan-Id"
	HEADER_PLAN_IPFS_STORAGE    string = "Plan-Storage"
	HEADER_IPFS_STORAGE         string = "Ipfs-Storage"
	HEADER_JTI                  string = "jti"
)
const (
	INSUFFICIENT_SCOPE_ERROR       string = "INSUFFICIENT_SCOPE_ERROR"
	USER_AGENT_CHANGED             string = "USER_AGENT_CHANGE"
	INVALID_TOKEN_ERROR            string = "INVALID_TOKEN_ERROR"
	INVALID_APP_ID                 string = "INVALID_APP_ID"
	INVALID_CUSTOMER_ID            string = "INVALID_CUSTOMER_ID"
	PARAM_NETWORK_ID               string = "network"
	PARAM_OFFSET                   string = "o"
	PARAM_MAX_ROWS                 string = "n"
	CORE_VIEW_WEIGHT_NAME_DEFAULT  string = "CORE_VIEW"
	CORE_VIEW_WEIGHT_VALUE_DEFAULT string = "1"
)
