package commons

import (
	"reflect"
	"regexp"
	"unicode"
)

var (
	emailRegex   = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	NumbersRegex = regexp.MustCompile("^[0-9]+$")
)

// IsEmailValid checks if a mail is valid
func IsEmailValid(e string) bool {
	if len(e) < 3 && len(e) > 254 {
		return false
	}

	return emailRegex.MatchString(e)
}

func CheckPasswordSafety(s string, minLengh, maxLenght uint8) bool {
	var number, upper, lower, special bool
	// var letters uint8

	if len(s) < int(minLengh) || len(s) > int(maxLenght) {
		return false
	}

	for _, c := range s {
		switch {
		case unicode.IsNumber(c):
			number = true
		case unicode.IsUpper(c):
			upper = true
			// letters++
		case unicode.IsLower(c):
			lower = true
			// letters++
		case unicode.IsPunct(c) || unicode.IsSymbol(c):
			special = true
		// case unicode.IsLetter(c) || c == ' ':
		// 	letters++
		default:
			//return false, false, false, false
		}
	}

	return number && upper && lower && special
}

func IsNil(i interface{}) bool {
	if i == nil {
		return true
	}
	switch reflect.TypeOf(i).Kind() {
	case reflect.Ptr, reflect.Map, reflect.Array, reflect.Chan, reflect.Slice:
		return reflect.ValueOf(i).IsNil()
	}
	return false
}
