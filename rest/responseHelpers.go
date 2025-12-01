package rest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/bitsbuster/utils/v2/errors"
	"github.com/bitsbuster/utils/v2/log"
	"github.com/go-http-utils/headers"
)

type ErrorDTO struct {
	Code      string    `json:"code"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

// NewErrorDTO returns a new ErrorDTO
func NewErrorDTO(code, message string) ErrorDTO {
	e := ErrorDTO{code, message, time.Now()}
	return e
}

func ReturnError(w http.ResponseWriter, err error, httpStatus int) {

	if err != nil {

		if s, ok := err.(*errors.CommonsError); ok {
			w.Header().Add(headers.ContentType, "application/json")
			errorDTO := NewErrorDTO(s.Code, s.Message)
			w.WriteHeader(httpStatus)
			errorMessage, _ := json.Marshal(errorDTO)

			fmt.Fprint(w, string(errorMessage))
		} else {
			log.Warnln(nil, "Use ReturnRawError instead of ReturnError")
			ReturnRawError(w, err.Error(), err.Error(), httpStatus)
		}
	} else {
		log.Errorf(nil, "Error is null, nothing written to response writter")
	}
}

// Returns a Raw error writting the code and the message received
func ReturnRawError(w http.ResponseWriter, code, message string, status int) {

	w.Header().Add(headers.ContentType, "application/json")

	errorDTO := NewErrorDTO(code, message)
	w.WriteHeader(status)
	errorMessage, _ := json.Marshal(errorDTO)

	fmt.Fprint(w, string(errorMessage))

}

func ReturnInternalServerError(w http.ResponseWriter, code, message string) {
	ReturnRawError(w, code, message, http.StatusInternalServerError)
}

func ReturnResponseToClient(w http.ResponseWriter, value interface{}) {
	ReturnResponseToClientWithStatus(w, value, http.StatusOK)
}

func ReturnResponseToClientWithStatus(w http.ResponseWriter, value interface{}, httpStatus int) {
	w.Header().Add(headers.ContentType, "application/json")
	w.WriteHeader(httpStatus)
	b, err := json.Marshal(value)
	if err != nil {
		//TODO: Error marshalling
	} else {
		fmt.Fprint(w, string(b))
	}

}

func GenerateStreamResponse(w http.ResponseWriter, r *http.Response, ctx context.Context, contentType string) error {
	w.Header().Set("Content-Type", contentType+"; charset=utf-8")
	w.Header().Set("Transfer-Encoding", "chunked")
	w.WriteHeader(http.StatusOK)

	buf := make([]byte, 512)
	for {
		n, err := r.Body.Read(buf)
		if n > 0 {
			if _, writeErr := w.Write(buf[:n]); writeErr != nil {
				log.Errorf(&ctx, "Error writing to stream: %+v", writeErr)
				break
			}
			w.(http.Flusher).Flush()
		}
		if err != nil {
			if err == io.EOF {
				log.Infof(&ctx, "End of stream")
				break
			}
			log.Errorf(&ctx, "Error reading stream: %+v", err)
			http.Error(w, "Error reading stream", http.StatusInternalServerError)
			return err
		}
	}
	return nil
}