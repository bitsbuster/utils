package interceptor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/bitsbuster/utils/v2/log"
	"github.com/bitsbuster/utils/v2/types"
	"github.com/gorilla/mux"
)

type CheckWeightWithDB func(types.SqlUuid, string) (*uint64, error)

type WeightContainer struct {
	CheckWeightWithDB CheckWeightWithDB
}
type LogResponseWriter struct {
	http.ResponseWriter
	statusCode int
	// serviceId  uint64
	buf bytes.Buffer
}

func NewLogResponseWriter(w http.ResponseWriter) *LogResponseWriter {
	return &LogResponseWriter{ResponseWriter: w}
}

func (w *LogResponseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *LogResponseWriter) Write(body []byte) (int, error) {
	w.buf.Write(body)
	return w.ResponseWriter.Write(body)
}

type BodyRequestInfo struct {
	ServiceID   uint64         `json:"serviceId"`
	AppId       *types.SqlUuid `json:"appId"`
	RequestBody []byte         `json:"requestBody"`
	Body        []byte         `json:"body"`
	Username    string         `json:"username"`
	CustomerID  types.SqlUuid  `json:"customerId"`
	Url         string         `json:"url"`
	Ip          string         `json:"ip"`
	Method      string         `json:"method"`
	HttpStatus  int            `json:"httpStatus"`
	TimeUsed    time.Duration  `json:"timeUsed"`
	RequestTime time.Time      `json:"requestTime"`
}

// Returns the json string representation
func (n *BodyRequestInfo) ToJson() string {

	bytes, err := json.Marshal(n)
	if err != nil {
		return ""
	}

	return string(bytes)
}

type ApiReqMiddleware func(BodyRequestInfo)

func SendApiReqMessage(f ApiReqMiddleware) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			ctx := r.Context()

			startTime := time.Now()

			bodyRequestInfo := BodyRequestInfo{}

			body, err := io.ReadAll(r.Body)
			if err != nil {
				log.Errorf(&ctx, "Error reading request body %+v", err)
			} else {
				bodyRequestInfo.RequestBody = body
				r.Body = io.NopCloser(bytes.NewBuffer(body))
			}
			bodyRequestInfo.RequestTime = startTime

			logRespWriter := NewLogResponseWriter(w)
			next.ServeHTTP(logRespWriter, r)

			bodyRequestInfo.Body = logRespWriter.buf.Bytes()
			bodyRequestInfo.Url = fmt.Sprintf("%s%s", r.Host, r.URL)
			bodyRequestInfo.Ip = getRequesterIp(r)
			bodyRequestInfo.Method = r.Method
			bodyRequestInfo.Username = r.Header.Get(HEADER_USER_NAME)
			bodyRequestInfo.CustomerID, _ = types.StringToSqlUuid(r.Header.Get(HEADER_CUSTOMER_ID))
			if appId := r.Header.Get(HEADER_APP_ID); len(appId) > 0 {
				kk, _ := types.StringToSqlUuid(appId)
				bodyRequestInfo.AppId = &kk
			}
			bodyRequestInfo.HttpStatus = logRespWriter.statusCode
			bodyRequestInfo.TimeUsed = time.Since(startTime)

			f(bodyRequestInfo)

		})
	}
}

func getRequesterIp(r *http.Request) string {

	if r.Header.Get("Cf-Connecting-Ip") != "" {
		return strings.Split(r.Header.Get("Cf-Connecting-Ip"), ":")[0]
	} else if r.Header.Get("X-Forwarded-For") != "" {
		return strings.Split(r.Header.Get("X-Forwarded-For"), ":")[0]
	} else if r.Header.Get("Host") != "" {
		return strings.Split(r.Header.Get("Host"), ":")[0]
	} else if r.RemoteAddr != "" {
		// return strings.Split(r.RemoteAddr, ":")[0]
		return r.RemoteAddr
	}
	return ""
}
