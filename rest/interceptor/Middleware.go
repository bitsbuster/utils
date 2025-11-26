package interceptor

import (
	"net/http"

	"github.com/bitsbuster/utils/v2/log"
	"github.com/bitsbuster/utils/v2/rest/jwt"
)

type ErrorDTO struct {
	// The error code
	// in: string
	Code string `json:"code"`
	// The error message
	// in: string
	Message string `json:"message"`
}

// NewErrorDTO returns a new ErrorDTO
func NewErrorDTO(code, message string) ErrorDTO {
	e := ErrorDTO{code, message}

	return e
}

// ServiceConfig contains the ServiceID and Environment values of the application that uses Middleware to secure access to endpoints.
type ServiceConfig struct {
	ServiceID   uint64
	Environment uint8
}

// Interface used to execute SecurityTokenInterceptor url filtering for authorization
type RoleValidator func(request *http.Request, customerInfo *jwt.CustomerInfo) bool

// MiddlewareInterceptor intercepts an HTTP handler invocation, it is passed both response writer and request
// which after interception can be passed onto the handler function.
type MiddlewareInterceptor func(http.ResponseWriter, *http.Request, http.HandlerFunc)

// MiddlewareHandlerFunc builds on top of http.HandlerFunc, and exposes API to intercept with MiddlewareInterceptor.
// This allows building complex long chains without complicated struct manipulation
type MiddlewareHandlerFunc http.HandlerFunc

// Intercept returns back a continuation that will call install middleware to intercept
// the continuation call.
func (cont MiddlewareHandlerFunc) Intercept(mw MiddlewareInterceptor) MiddlewareHandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if request == nil {
			writer.WriteHeader(http.StatusBadRequest)
			log.Errorln(nil, ("***ERROR***: Missing Request"))
			return
		} else {
			mw(writer, request, http.HandlerFunc(cont))
		}
	}
}

// MiddlewareChain is a collection of interceptors that will be invoked in there index order
type MiddlewareChain []MiddlewareInterceptor

// Handler allows hooking multiple middleware in single call.
func (chain MiddlewareChain) Handler(handler http.HandlerFunc) http.Handler {
	curr := MiddlewareHandlerFunc(handler)
	for i := len(chain) - 1; i >= 0; i-- {
		mw := chain[i]
		curr = curr.Intercept(mw)
	}

	return http.HandlerFunc(curr)
}
