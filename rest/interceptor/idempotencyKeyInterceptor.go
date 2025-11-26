package interceptor

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/bitsbuster/utils/v2/log"
	"github.com/bitsbuster/utils/v2/rest"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

type ValidateIdempotency func(ctx context.Context, key string) (*rest.APIResponse, error)
type CacheResponse func(ctx context.Context, key string, responseBody []byte)

// responseWrapper captura la respuesta escrita en un buffer.
type responseWrapper struct {
	http.ResponseWriter
	buf *bytes.Buffer
}

// Write implementa el método de la interfaz http.ResponseWriter.
// Escribe los bytes tanto en el buffer como en el ResponseWriter original.
func (rw *responseWrapper) Write(b []byte) (int, error) {
	// Escribe en nuestro buffer para poder leer la respuesta más tarde.
	rw.buf.Write(b)
	// Llama al método Write del ResponseWriter real para enviar la respuesta.
	return rw.ResponseWriter.Write(b)
}

func IdempotencyKeyInterceptor(validateIdempotency ValidateIdempotency, cacheResponse CacheResponse) mux.MiddlewareFunc {

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			idempotencyKey := r.Header.Get(HEADER_IDEMPOTENCY_KEY)

			if r.Method == http.MethodPost || r.Method == http.MethodPut {
				if _, err := uuid.Parse(idempotencyKey); err != nil {
					log.Errorln(&ctx, "Invalid idempotency key")
					w.WriteHeader(http.StatusBadRequest)
					return
				}

				response, err := validateIdempotency(ctx, idempotencyKey)

				if err != nil {
					log.Errorf(&ctx, "failed validating idempotency")
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				if response != nil {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(response)
					return
				}

				// Envuelve el ResponseWriter para capturar la respuesta
				wrappedWriter := &responseWrapper{
					ResponseWriter: w,
					buf:            bytes.NewBuffer(nil),
				}

				next.ServeHTTP(wrappedWriter, r)

				responseBody := wrappedWriter.buf.Bytes()
				cacheResponse(ctx, idempotencyKey, responseBody)

				log.Tracef(&ctx, "idempotency key {%s} processed. Response stored in cache", idempotencyKey)
			} else {
				next.ServeHTTP(w, r)
			}
		})
	}
}
