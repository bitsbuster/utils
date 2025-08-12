package errors

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

// New returns an error that formats as the given code and text (the message).
// Each call to New returns a distinct error value even if the text is identical.
func New(code string, text string) error {
	return &CommonsError{code, text}
}

// CommonsError is a trivial implementation of error.
type CommonsError struct {
	Code    string
	Message string
}

// Returns the CommonsError code
//
// If e is not type of CommonsError returns an empty string
func Code(e error) string {
	if t, ok := e.(*CommonsError); ok {
		return t.Code
	}
	return ""
}

// Returns the CommonsError message
//
// If e is not type of CommonsError returns an empty string
func Message(e error) string {
	if t, ok := e.(*CommonsError); ok {
		return t.Message
	}
	return ""
}
func (e CommonsError) Error() string {
	return e.Code + " - " + e.Message
}

func GetCommonsError(err error) *CommonsError {
	if w, ok := err.(*CommonsError); ok {
		return w
	}
	return &CommonsError{Message: err.Error()}
}

func (e *CommonsError) String() string {
	return fmt.Sprintf("%s (%s)", e.Message, e.Code)
}

// Implements the driver.Valuer interface to be able to insert it into MySQL
func (e CommonsError) Value() (driver.Value, error) {
	return json.Marshal(e)
}

// Implements the sql.Scanner interface to be able to read it from MySQL
func (e *CommonsError) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return New("ERROR_EXPECTS_BYTE_ARRAY", "expects []byte")
	}
	return json.Unmarshal(b, e)
}

// Implements the json.Marshaler interface to control JSON serialization.
func (e CommonsError) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}{
		Code:    e.Code,
		Message: e.Message,
	})
}
