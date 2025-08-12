package contextkeys

type contextKey string

const (
	CtxKeyUser      contextKey = "user"
	CtxKeyPath      contextKey = "path"
	CtxKeyRequestID contextKey = "request_id"
	CtxKeyMethod    contextKey = "method"
	CtxKeyStartTime contextKey = "start_time"
)
