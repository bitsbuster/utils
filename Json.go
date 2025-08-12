package commons

import "encoding/json"

func ToJson(n interface{}) (string, bool) {

	bytes, err := json.Marshal(n)
	if err != nil {
		return "", false
	}

	return string(bytes), true
}
