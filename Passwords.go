package commons

import (
	"crypto/rand"
	"encoding/base64"
	"unicode"

	"github.com/bitsbuster/utils/v2/log"
	"golang.org/x/crypto/bcrypt"
)

const (
	wide    string = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	utm     string = "123456789ABCDEFGHIJKLMNPQRSTUVWXYZ"
	numbers string = "0123456789"
)

// GenerateRandomBytes returns securely generated random bytes.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

// GenerateRandomString returns a securely generated random string.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomString(n int) (*string, error) {
	return generateRandomStringCode(n, wide)
}

// GenerateUpperCaseAndNumbersRandomString returns a securely generated random string
// containing n uppercase letters (!O) and numbers (!0).
//
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateUpperCaseAndNumbersRandomString(n int) (*string, error) {
	return generateRandomStringCode(n, utm)
}

// GenerateNumbersRandomString returns a securely generated random string
// containing n numbers from 0 to 9.
//
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateNumbersRandomString(n int) (*string, error) {
	return generateRandomStringCode(n, numbers)
}

// GenerateRamdomString returns a securely generated random string
// containing n characters from source.
//
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRamdomString(n int, source string) (*string, error) {
	return generateRandomStringCode(n, source)

}
func generateRandomStringCode(n int, letters string) (*string, error) {
	bytes, err := GenerateRandomBytes(n)
	if err != nil {
		return nil, err
	}
	for i, b := range bytes {
		bytes[i] = letters[b%byte(len(letters))]
	}
	result := string(bytes)
	return &result, nil
}

// GenerateRandomStringURLSafe returns a URL-safe, base64 encoded
// securely generated random string.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomStringURLSafe(n int) (string, error) {
	b, err := GenerateRandomBytes(n)
	return base64.URLEncoding.EncodeToString(b), err
}

func HashAndSalt(pwd *[]byte) string {

	// Use GenerateFromPassword to hash & salt pwd.
	// MinCost is just an integer constant provided by the bcrypt
	// package along with DefaultCost & MaxCost.
	// The cost can be any value you want provided it isn't lower
	// than the MinCost (4)
	hash, err := bcrypt.GenerateFromPassword(*pwd, 5)
	if err != nil {
		log.Println(nil, err)
	}
	// GenerateFromPassword returns a byte slice so we need to
	// convert the bytes to a string and return it
	return string(hash)

}
func ComparePasswords(hashedPwd string, plainPwd string) bool {
	// Since we'll be getting the hashed password from the DB it
	// will be a string so we'll need to convert it to a byte slice
	byteHash := []byte(hashedPwd)
	err := bcrypt.CompareHashAndPassword(byteHash, []byte(plainPwd))
	if err != nil {
		log.Println(nil, err)
		return false
	}

	return true
}

// Check the password security:
// They have to be at least on upper, one lower, a number and a spacial charcter
func CheckPasswordSecurity(s string, minlength, maxlengh int) bool {
	var number, upper, lower, special bool
	// var letters uint8

	if len(s) < minlength || len(s) > maxlengh {
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
