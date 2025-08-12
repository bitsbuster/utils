package commons

import (
	"strings"
	"unicode"

	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

func isMn(r rune) bool {
	return unicode.Is(unicode.Mn, r) // Mn: nonspacing marks
}

func RemoveDiacritics(s string) *string {

	b := make([]byte, len(s))

	t := transform.Chain(norm.NFD, transform.RemoveFunc(isMn), norm.NFC)
	nDst, _, e := t.Transform(b, []byte(s), true)
	if e != nil {
		panic(e)
	}

	value := string(b[:nDst])

	// fmt.Println(value)

	return &value
}

func FindSubstringOcurrences(text, substring string) ([]int, error) {
	index := -1
	appears := make([]int, 0)
	for {
		if index == len(text) {
			break
		}
		text = text[index+1:]
		index2 := strings.Index(text, substring)
		if index2 == -1 {
			break
		}
		if len(appears) == 0 {
			appears = append(appears, index+index2+1)
		} else {
			appears = append(appears, appears[len(appears)-1]+len(substring)+index2+1)
		}
		// Increment the index to search for the next occurrence
		index = index2 + len(substring)
	}
	return appears, nil

}

// ReverseString reverses a string
func ReverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}
