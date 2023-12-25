package next

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unsafe"
)

type ARG_SIGACTION struct {
	ARG_STRUCT
}

func (this *ARG_SIGACTION) Setup() {
	this.ARG_STRUCT.Setup()
}

func (this *ARG_SIGACTION) Parse(ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	if !parse_more {
		return fmt.Sprintf("0x%x", ptr)
	}
	if this.GetStructLen(buf) != 0 {
		var arg Arg_Sigaction
		if err := binary.Read(buf, binary.LittleEndian, &arg.Sigaction); err != nil {
			panic(err)
		}
		return fmt.Sprintf("0x%x%s", ptr, arg.Format())
	}
	return fmt.Sprintf("0x%x", ptr)
}

func init() {
	Register(&ARG_SIGACTION{}, "sigaction", TYPE_SIGACTION, uint32(unsafe.Sizeof(Sigaction{})))
}
