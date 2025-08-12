package types

type UserRole uint8

const (
	ApiUser UserRole = iota + 1
	AppUser
	Manager
	Console
	_
	_
	_
	_
	_
	Admin
)

type SortUint64 []uint64

func (a SortUint64) Len() int           { return len(a) }
func (a SortUint64) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a SortUint64) Less(i, j int) bool { return a[i] < a[j] }
