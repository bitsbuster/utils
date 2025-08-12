package interceptor

import (
	"net/http"
	"runtime/debug"

	"github.com/bitsbuster/utils/log"
)

// Recoverer is an interceptor that recovers from panics, logs the panic (and the stacktrace),
// and returns a HTTP 500 (Internal Server Error) status if
// possible.
func Recoverer(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rvr := recover(); rvr != nil {
				if rvr == http.ErrAbortHandler {
					// we don't recover http.ErrAbortHandler so the response
					// to the client is aborted
					panic(rvr)
				}

				log.Errorf(nil, "Recovering panic error: %+v", rvr)
				log.Errorf(nil, "Stack: %+v", string(debug.Stack()))

				if r.Header.Get("Connection") != "Upgrade" {
					w.WriteHeader(http.StatusInternalServerError)
				}
			}
		}()

		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}
