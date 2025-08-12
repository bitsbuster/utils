package commons

// Checks if an string array contains a given string and returns true if it is present
func ArrayContainsString(arr *[]string, str string) bool {
	for _, a := range *arr {
		if a == str {
			return true
		}
	}

	return false
}

func ArrayContainsUint64(arr *[]uint64, value uint64) bool {
	for _, a := range *arr {
		if a == value {
			return true
		}
	}

	return false
}
