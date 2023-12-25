package next

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unsafe"
)

type ARG_SIGINFO struct {
	ARG_STRUCT
}

func (this *ARG_SIGINFO) Setup() {
	this.ARG_STRUCT.Setup()
}

func (this *ARG_SIGINFO) Parse(ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	if !parse_more {
		return fmt.Sprintf("0x%x", ptr)
	}
	if this.GetStructLen(buf) != 0 {
		var arg Arg_SigInfo
		if err := binary.Read(buf, binary.LittleEndian, &arg.SigInfo); err != nil {
			panic(err)
		}
		return fmt.Sprintf("0x%x%s", ptr, arg.Format())
	}
	return fmt.Sprintf("0x%x", ptr)
}

func init() {
	Register(&ARG_SIGINFO{}, "siginfo", TYPE_SIGINFO, uint32(unsafe.Sizeof(SigInfo{})))
}
