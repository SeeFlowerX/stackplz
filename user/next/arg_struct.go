package next

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"stackplz/user/util"
)

type ARG_STRUCT struct {
	ArgType
}

func (this *ARG_STRUCT) Setup() {
	this.AddOp(SaveStruct(uint64(this.Size)))
}

func (this *ARG_STRUCT) Clone() IArgType {
	p, ok := (this.ArgType.Clone()).(*ArgType)
	if !ok {
		panic("...")
	}
	return &ARG_STRUCT{*p}
}

func (this *ARG_STRUCT) Parse(ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	if !parse_more {
		return fmt.Sprintf("0x%x", ptr)
	}
	if this.ParseCB != nil {
		return this.ParseCB(this, ptr, buf, parse_more)
	}

	// 不同结构体需要分别实现解析
	panic("....")
}

func (this *ARG_STRUCT) DumpBuffer(buf *bytes.Buffer) string {
	// 调试使用 直接 hexdump
	payload := make([]byte, this.Size)
	if err := binary.Read(buf, binary.LittleEndian, &payload); err != nil {
		panic(err)
	}
	return util.HexDumpGreen(payload)
}

func (this *ARG_STRUCT) GetStructLen(buf *bytes.Buffer) uint32 {
	// 这里负责解析出 实际读取的结构体 大小
	// 如果失败了 那么就是 0 那么就不需要再进一步解析结果了
	var arg Arg_str
	if err := binary.Read(buf, binary.LittleEndian, &arg); err != nil {
		panic(err)
	}
	if arg.Len > 0 && arg.Len != this.Size {
		panic(fmt.Sprintf("check %s", this.Name))
	}
	return arg.Len
}

func init() {
	Register(&ARG_STRUCT{}, "struct", TYPE_STRUCT, 0)
}
