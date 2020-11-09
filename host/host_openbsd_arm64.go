// +build openbsd
// +build arm64
// Code generated by cmd/cgo -godefs; DO NOT EDIT.
// cgo -godefs host/types_openbsd.go

package host

const (
	sizeofPtr      = 0x8
	sizeofShort    = 0x2
	sizeofInt      = 0x4
	sizeofLong     = 0x8
	sizeofLongLong = 0x8
	sizeOfUtmp     = 0x130
)

type (
	_C_short     int16
	_C_int       int32
	_C_long      int64
	_C_long_long int64
)

type Utmp struct {
	Line [8]uint8
	Name [32]uint8
	Host [256]uint8
	Time int64
}
type Timeval struct {
	Sec  int64
	Usec int64
}
