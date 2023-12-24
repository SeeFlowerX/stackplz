package next

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type ARG_BUFFER struct {
	ArgType
}

func (this *ARG_BUFFER) SetupRegAsReadLen(reg_index uint32) *ARG_BUFFER {
	at := ARG_BUFFER{}
	at.Name = this.Name
	at.Alias = this.Alias
	at.Size = this.Size
	at.AddOp(OPC_SET_READ_LEN.NewValue(uint64(this.Size)))
	at.AddOp(BuildReadRegLen(uint64(reg_index)))
	at.AddOp(OPC_SAVE_STRUCT)
	return &at
}

func (this *ARG_BUFFER) Setup() {
	this.SetupSaveStruct()
}

func (this *ARG_BUFFER) Parse(ptr uint64, buf *bytes.Buffer) string {
	var arg Arg_str
	if err := binary.Read(buf, binary.LittleEndian, &arg); err != nil {
		panic(err)
	}
	payload := make([]byte, arg.Len)
	if err := binary.Read(buf, binary.LittleEndian, &payload); err != nil {
		panic(err)
	}
	return fmt.Sprintf("0x%x%s", ptr, arg.Format(payload))
}

func RegAsBufferReadLen(p IArgType, reg_index uint32) IArgType {
	at, ok := (p).(*ARG_BUFFER)
	if !ok {
		panic("...")
	}
	return at.SetupRegAsReadLen(reg_index)
}

func init() {
	Register(&ARG_BUFFER{}, "buffer", TYPE_BUFFER, MAX_BUF_READ_SIZE)
}
