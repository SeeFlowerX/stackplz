package next

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unsafe"
)

type ARG_STACK_T struct {
	ARG_STRUCT
}

func (this *ARG_STACK_T) Setup() {
	this.ARG_STRUCT.Setup()
}

func (this *ARG_STACK_T) Parse(ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	if !parse_more {
		return fmt.Sprintf("0x%x", ptr)
	}
	if this.GetStructLen(buf) != 0 {
		var arg Arg_Stack_t
		if err := binary.Read(buf, binary.LittleEndian, &arg.Stack_t); err != nil {
			panic(err)
		}
		return fmt.Sprintf("0x%x%s", ptr, arg.Format())
	}
	return fmt.Sprintf("0x%x", ptr)
}

func init() {
	Register(&ARG_STACK_T{}, "stack_t", TYPE_STACK_T, uint32(unsafe.Sizeof(Stack_t{})))
}
