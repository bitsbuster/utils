package interceptor

import (
	"context"
	"math"
	"net"
	"net/http"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/bitsbuster/utils/v2/contextkeys"
	"github.com/bitsbuster/utils/v2/log"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

type requestInfo struct {
	url       string
	requestID string
}
type key int

const requestIDKey key = 0

var (
	totalRequests         uint64
	maxConcurrentRequests int32
	concurrentRequests    int32
	ch                    chan requestInfo
)

func LaunchMemStats() {
	ch = make(chan requestInfo)
	if log.LogLevel == log.TRACE {
		go memStats()
	}
}

// Intercepts the request and calculates the total run time from start to finish
func NewElapsedTimeInterceptor() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			startTime := float64(time.Now().UnixNano()) / float64(time.Millisecond)
			// idRequest, _ := crypto.GetDataHash(time.Now())
			// idRequestStr := base64.RawStdEncoding.EncodeToString(idRequest[:])
			// ctx := context.WithValue(r.Context(), requestIDKey, idRequestStr)
			// requestInfo := requestInfo{url: r.URL.Path, hash: base64.RawStdEncoding.EncodeToString(idRequest[:])}

			ctx := r.Context()
			ctx = context.WithValue(ctx, contextkeys.CtxKeyRequestID, uuid.New().String())
			ctx = context.WithValue(ctx, contextkeys.CtxKeyPath, r.URL.Path)
			ctx = context.WithValue(ctx, contextkeys.CtxKeyMethod, r.Method)
			requestInfo := requestInfo{url: r.URL.Path, requestID: ctx.Value(contextkeys.CtxKeyRequestID).(string)}

			if log.LogLevel == log.TRACE {

				ch <- requestInfo

				atomic.AddInt32(&concurrentRequests, 1)
				if atomic.LoadInt32(&concurrentRequests) > atomic.LoadInt32(&maxConcurrentRequests) {
					atomic.StoreInt32(&maxConcurrentRequests, atomic.LoadInt32(&concurrentRequests))
				}
				atomic.AddUint64(&totalRequests, 1)
			}
			if r == nil {
				w.WriteHeader(http.StatusBadRequest)
				log.Errorf(nil, "%s - Missing Request", requestInfo.requestID)
				return
			}

			remoteAddress := GetRequesterIp(r)
			ip, _, _ := net.SplitHostPort(remoteAddress)
			log.Infof(nil, "**** %s - New Request Arrived: Requester ip is %s; Request info: [%s %s%s]", requestInfo.requestID, ip, r.Method, r.Host, r.URL)

			defer func() {
				endTime := float64(time.Now().UnixNano()) / float64(time.Millisecond)
				elapsed := float64((endTime - startTime) / 1000)
				log.Infof(nil, "**** %s - Time consumed for query to %s is %.2f seconds", requestInfo.requestID, r.URL.Path, math.Round(elapsed*100)/100)
				if log.LogLevel == log.TRACE {

					atomic.AddInt32(&concurrentRequests, -1)
					ch <- requestInfo
				}
			}()
			r.Header.Add(HEADER_REMOTE_IP, ip)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func GetRequestID(ctx context.Context) string {
	if requestID, ok := ctx.Value(requestIDKey).(string); ok {
		return requestID
	}
	return "UNKNOWN"
}

func memStats() {
	var m runtime.MemStats
	for {
		requestInfo := <-ch
		runtime.ReadMemStats(&m)
		log.Debugf(
			nil,
			"**** %s - Request to: %s - Total connections count: %d; Current connections count: %d; Max concurrent connections count: %d; Alloc = %v MiB; TotalAlloc = %v MiB; Sys = %v MiB; Num gc cycles = %v",
			requestInfo.requestID,
			requestInfo.url,
			atomic.LoadUint64(&totalRequests),
			atomic.LoadInt32(&concurrentRequests),
			atomic.LoadInt32(&maxConcurrentRequests),
			m.Alloc/1024/1024,
			m.TotalAlloc/1024/1024,
			m.Sys/1024/1024,
			m.NumGC,
		)

	}
}
