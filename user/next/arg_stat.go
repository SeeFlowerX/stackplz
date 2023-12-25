package next

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"
)

type ARG_STAT struct {
	ARG_STRUCT
}

func (this *ARG_STAT) Setup() {
	this.ARG_STRUCT.Setup()
}

func (this *ARG_STAT) Parse(ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	if !parse_more {
		return fmt.Sprintf("0x%x", ptr)
	}
	if this.GetStructLen(buf) != 0 {
		var arg Arg_Stat_t
		if err := binary.Read(buf, binary.LittleEndian, &arg.Stat_t); err != nil {
			panic(err)
		}
		return fmt.Sprintf("0x%x%s", ptr, arg.Format())
	}
	return fmt.Sprintf("0x%x", ptr)
}

func init() {
	Register(&ARG_STAT{}, "stat", TYPE_STAT, uint32(unsafe.Sizeof(syscall.Stat_t{})))
}
