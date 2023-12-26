package next

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unsafe"
)

type ARG_SIGINFO struct {
	ARG_STRUCT
	// FormatType uint32
}

func (this *ARG_SIGINFO) Setup() {
	this.ARG_STRUCT.Setup()
}

// func (this *ARG_SIGINFO) SetFormat(format_type uint32) IArgType {
// 	// FormatType 这种应该抽取出来 还有 Clone
// 	at := ARG_SIGINFO{}
// 	at.Name = this.Name
// 	at.Alias = this.Alias
// 	at.Size = this.Size
// 	at.FormatType = this.FormatType
// 	return &at
// }

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

// func SetFormat(p IArgType, format_type uint32) IArgType {
// 	at, ok := p.(*ARG_SIGINFO)
// 	if !ok {
// 		panic("...")
// 	}
// 	return at.SetFormat(format_type)
// }

func init() {
	Register(&ARG_SIGINFO{}, "siginfo", TYPE_SIGINFO, uint32(unsafe.Sizeof(SigInfo{})))
}
