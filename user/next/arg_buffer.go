package next

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type ARG_BUFFER struct {
	ARG_STRUCT
}

func (this *ARG_BUFFER) SetupValueAsReadLen(value uint32) *ARG_BUFFER {
	at := ARG_BUFFER{}
	at.Name = this.Name
	at.Alias = this.Alias
	at.Size = value
	at.AddOp(OPC_SET_READ_LEN.NewValue(uint64(at.Size)))
	at.AddOp(OPC_SAVE_STRUCT)
	return &at
}

func (this *ARG_BUFFER) SetupRegAsReadLen(reg_index uint32) *ARG_BUFFER {
	at := ARG_BUFFER{}
	at.Name = this.Name
	at.Alias = this.Alias
	at.Size = this.Size
	at.AddOp(OPC_SET_READ_LEN.NewValue(uint64(at.Size)))
	at.AddOp(BuildReadRegLen(uint64(reg_index)))
	at.AddOp(OPC_SAVE_STRUCT)
	return &at
}

func (this *ARG_BUFFER) Setup() {
	this.ARG_STRUCT.Setup()
}

func (this *ARG_BUFFER) Parse(ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	if !parse_more {
		return fmt.Sprintf("0x%x", ptr)
	}
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

func ValueAsBufferReadLen(p IArgType, value uint32) IArgType {
	at, ok := (p).(*ARG_BUFFER)
	if !ok {
		panic("...")
	}
	return at.SetupValueAsReadLen(value)
}

func init() {
	Register(&ARG_BUFFER{}, "buffer", TYPE_BUFFER, MAX_BUF_READ_SIZE)
}
