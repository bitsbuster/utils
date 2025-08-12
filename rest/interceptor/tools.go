package interceptor

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

func returnErrorToCustomer(w http.ResponseWriter, errorDTO ErrorDTO) {
	b, err := json.Marshal(errorDTO)
	if err != nil {
		panic(err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	fmt.Fprint(w, string(b))
}

// Strips 'Bearer ' prefix from bearer token string
func StripBearerPrefixFromTokenString(tok string) (string, error) {
	// Should be a bearer token
	if len(tok) > 6 && strings.ToUpper(tok[0:7]) == "BEARER " {
		return tok[7:], nil
	}
	return tok, nil
}

func GetRequesterIp(r *http.Request) string {

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
