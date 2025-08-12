package arrays

import "reflect"

// SliceToArray Converts an bytes slice to an array of size "length" and returns an interface with the result
//
// In Go, arrays have a fixed size that must be known at compile time, which makes converting a slice to an array of variable size directly not possible. However, and using reflection we can create an array with the appropiate size at runtime.
//
//	params
//	 slice contains the bytes slice
//	 length sets the size of the resulting array
//
//	returns
//	 an interface{} with the fixed size array
func SliceToArray(slice []byte, length int) interface{} {
	// Creates a []byte with the size set by length using reflection
	arrayType := reflect.ArrayOf(length, reflect.TypeOf(byte(0)))
	array := reflect.New(arrayType).Elem()

	// Copia los elementos del slice al array
	reflect.Copy(array, reflect.ValueOf(slice))

	return array.Interface()
}
