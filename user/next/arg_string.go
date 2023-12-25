package next

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"stackplz/user/util"
)

type ARG_STRING struct {
	ArgType
}

func (this *ARG_STRING) Setup() {
	this.AddOp(OPC_SAVE_STRING)
}

func (this *ARG_STRING) Parse(ptr uint64, buf *bytes.Buffer) string {
	var arg Arg_str
	if err := binary.Read(buf, binary.LittleEndian, &arg); err != nil {
		panic(err)
	}
	payload := make([]byte, arg.Len)
	if err := binary.Read(buf, binary.LittleEndian, &payload); err != nil {
		panic(err)
	}
	return fmt.Sprintf("0x%x(%s)", ptr, util.B2STrim(payload))
}

func init() {
	Register(&ARG_STRING{}, "string", TYPE_STRING, MAX_BUF_READ_SIZE)
}
