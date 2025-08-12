package pointer

import "time"

// Returns a pointer to the v string
func String(v string) *string {
	return &v
}

// Returns a pointer to the v uint64
func Uint64(v uint64) *uint64 {
	return &v
}

// Returns a pointer to the v bool
func Bool(v bool) *bool {
	return &v
}

// Returns a pointer to the v int
func Int(v int) *int {
	return &v
}

// Returns a pointer to the v int64
func Int64(v int64) *int64 {
	return &v
}

// Returns a pointer to the v float64
func Float64(v float64) *float64 {
	return &v
}

// Returns a pointer to the v time
func Time(v time.Time) *time.Time {
	return &v
}
