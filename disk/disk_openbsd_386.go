// Code generated by cmd/cgo -godefs; DO NOT EDIT.
// cgo -godefs types_openbsd.go

package disk

const (
	sizeofPtr        = 0x4
	sizeofShort      = 0x2
	sizeofInt        = 0x4
	sizeofLong       = 0x4
	sizeofLongLong   = 0x8
	sizeofLongDouble = 0x8

	DEVSTAT_NO_DATA = 0x00
	DEVSTAT_READ    = 0x01
	DEVSTAT_WRITE   = 0x02
	DEVSTAT_FREE    = 0x03
)

const (
	sizeOfDiskstats = 0x60
)

type (
	_C_short       int16
	_C_int         int32
	_C_long        int32
	_C_long_long   int64
	_C_long_double int64
)

type Diskstats struct {
	Name       [16]int8
	Busy       int32
	Rxfer      uint64
	Wxfer      uint64
	Seek       uint64
	Rbytes     uint64
	Wbytes     uint64
	Attachtime Timeval
	Timestamp  Timeval
	Time       Timeval
}
type Timeval struct {
	Sec  int64
	Usec int32
}

type Diskstat struct{}
type Bintime struct{}
