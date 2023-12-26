package argtype

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"stackplz/user/next/config"
	"stackplz/user/util"
	"strconv"
	"unsafe"
)

// 基础类型

type ARG_NUM struct {
	ArgType
	FlagsParser *FlagsParser
	FormatType  uint32
}

func (this *ARG_NUM) Setup() {

}

// func (this *ARG_NUM) ParseFlags(flags int32) string {
// 	if this.FlagsParser != nil {
// 		return this.FlagsParser.Parse(flags)
// 	}
// 	return ""
// }

// func AttachFlagsParser(p IArgType, flags_parser *FlagsParser) IArgType {
// 	at := ARG_NUM{}
// 	at.Name = p.GetName()
// 	at.Alias = p.GetAlias()
// 	at.Size = p.GetSize()
// 	at.FlagsParser = flags_parser
// 	at.FormatType = at.FlagsParser.FormatType
// 	switch p.(type) {
// 	case *ARG_PTR:
// 		return &ARG_PTR{at, nil, false}
// 	case *ARG_INT:
// 		return &ARG_INT{at}
// 	case *ARG_UINT:
// 		return &ARG_UINT{at}
// 	case *ARG_INT8:
// 		return &ARG_INT8{at}
// 	case *ARG_INT16:
// 		return &ARG_INT16{at}
// 	case *ARG_INT32:
// 		return &ARG_INT32{at}
// 	case *ARG_INT64:
// 		return &ARG_INT64{at}
// 	case *ARG_UINT8:
// 		return &ARG_UINT8{at}
// 	case *ARG_UINT16:
// 		return &ARG_UINT16{at}
// 	case *ARG_UINT32:
// 		return &ARG_UINT32{at}
// 	case *ARG_UINT64:
// 		return &ARG_UINT64{at}
// 	}
// 	return &at
// }

// func NewNumFormat(p IArgType, format_type uint32) IArgType {
// 	at := ARG_NUM{}
// 	at.Name = p.GetName()
// 	at.Alias = p.GetAlias()
// 	at.Size = p.GetSize()
// 	at.FormatType = format_type
// 	switch p.(type) {
// 	case *ARG_PTR:
// 		return &ARG_PTR{at, nil, false}
// 	case *ARG_INT:
// 		return &ARG_INT{at}
// 	case *ARG_UINT:
// 		return &ARG_UINT{at}
// 	case *ARG_INT8:
// 		return &ARG_INT8{at}
// 	case *ARG_INT16:
// 		return &ARG_INT16{at}
// 	case *ARG_INT32:
// 		return &ARG_INT32{at}
// 	case *ARG_INT64:
// 		return &ARG_INT64{at}
// 	case *ARG_UINT8:
// 		return &ARG_UINT8{at}
// 	case *ARG_UINT16:
// 		return &ARG_UINT16{at}
// 	case *ARG_UINT32:
// 		return &ARG_UINT32{at}
// 	case *ARG_UINT64:
// 		return &ARG_UINT64{at}
// 	}
// 	return &at
// }

type ARG_PTR struct {
	ARG_NUM
	PtrArgType IArgType
	IsNum      bool
}

type ARG_INT struct {
	ARG_NUM
}

type ARG_UINT struct {
	ARG_NUM
}

type ARG_INT8 struct {
	ARG_NUM
}

type ARG_INT16 struct {
	ARG_NUM
}

type ARG_INT32 struct {
	ARG_NUM
}

type ARG_INT64 struct {
	ARG_NUM
}

type ARG_UINT8 struct {
	ARG_NUM
}

type ARG_UINT16 struct {
	ARG_NUM
}

type ARG_UINT32 struct {
	ARG_NUM
}

type ARG_UINT64 struct {
	ARG_NUM
}

func (this *ARG_PTR) Parse(ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	if !parse_more {
		return fmt.Sprintf("0x%x", ptr)
	}
	if this.PtrArgType != nil {
		if this.IsNum {
			var arg Arg_str
			// var arg Arg_str
			if err := binary.Read(buf, binary.LittleEndian, &arg); err != nil {
				panic(err)
			}
			var value uint64 = 0
			if arg.Len == 8 {
				if err := binary.Read(buf, binary.LittleEndian, &value); err != nil {
					panic(err)
				}
			}
			return fmt.Sprintf("0x%x(%s)", ptr, this.PtrArgType.Parse(value, buf, parse_more))
		}
		return this.PtrArgType.Parse(ptr, buf, parse_more)
	}
	return fmt.Sprintf("0x%x", ptr)
}

// func (this *ARG_PTR) SetupPtrType(p IArgType, is_num bool) IArgType {
// 	at := ARG_PTR{}
// 	at.Name = fmt.Sprintf("%s_%s", this.Name, p.GetName())
// 	at.Alias = this.Alias
// 	at.Size = p.GetSize()
// 	at.PtrArgType = p
// 	at.IsNum = is_num
// 	// 对于数字类型是需要的
// 	if at.IsNum {
// 		// 默认保存一个指针大小
// 		at.AddOp(SaveStruct(8))
// 	}
// 	at.AddOpList(p)
// 	return &at
// }

// func SetupPtrType(p IArgType, is_num bool) IArgType {
// 	at, ok := (GetArgType("ptr")).(*ARG_PTR)
// 	if !ok {
// 		panic("...")
// 	}
// 	return at.SetupPtrType(p, is_num)
// }

func (this *ARG_INT) Parse(ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	value_fix := int32(ptr)
	flags_fmt := ""
	if this.FlagsParser != nil {
		flags_fmt = this.FlagsParser.Parse(int32(value_fix))
	}
	switch this.FormatType {
	case FORMAT_NUM:
		return fmt.Sprintf("%d%s", value_fix, flags_fmt)
	case FORMAT_HEX_PURE:
		return fmt.Sprintf("%x%s", value_fix, flags_fmt)
	case FORMAT_HEX:
		return fmt.Sprintf("0x%x%s", value_fix, flags_fmt)
	case FORMAT_DEC:
		return fmt.Sprintf("%d%s", value_fix, flags_fmt)
	case FORMAT_OCT:
		return fmt.Sprintf("0o%03s%s", strconv.FormatInt(int64(value_fix), 8), flags_fmt)
	case FORMAT_BIN:
		return fmt.Sprintf("0b%s%s", strconv.FormatInt(int64(value_fix), 2), flags_fmt)
	default:
		return fmt.Sprintf("%d%s", value_fix, flags_fmt)
	}
}
func (this *ARG_UINT) Parse(ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	value_fix := uint32(ptr)
	flags_fmt := ""
	if this.FlagsParser != nil {
		flags_fmt = this.FlagsParser.Parse(int32(value_fix))
	}
	switch this.FormatType {
	case FORMAT_NUM:
		return fmt.Sprintf("%d%s", value_fix, flags_fmt)
	case FORMAT_HEX_PURE:
		return fmt.Sprintf("%x%s", value_fix, flags_fmt)
	case FORMAT_HEX:
		return fmt.Sprintf("0x%x%s", value_fix, flags_fmt)
	case FORMAT_DEC:
		return fmt.Sprintf("%d%s", value_fix, flags_fmt)
	case FORMAT_OCT:
		return fmt.Sprintf("0o%03s%s", strconv.FormatInt(int64(value_fix), 8), flags_fmt)
	case FORMAT_BIN:
		return fmt.Sprintf("0b%s%s", strconv.FormatInt(int64(value_fix), 2), flags_fmt)
	default:
		return fmt.Sprintf("%d%s", value_fix, flags_fmt)
	}
}
func (this *ARG_INT8) Parse(ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	value_fix := int8(ptr)
	value_fmt := fmt.Sprintf("%d", value_fix)
	if this.FlagsParser != nil {
		flags_fmt := this.FlagsParser.Parse(int32(value_fix))
		switch this.FormatType {
		case FORMAT_NUM:
			return fmt.Sprintf("%d%s", value_fix, flags_fmt)
		case FORMAT_HEX_PURE:
			return fmt.Sprintf("%x%s", value_fix, flags_fmt)
		case FORMAT_HEX:
			return fmt.Sprintf("0x%x%s", value_fix, flags_fmt)
		case FORMAT_DEC:
			return fmt.Sprintf("%d%s", value_fix, flags_fmt)
		case FORMAT_OCT:
			return fmt.Sprintf("0o%03s%s", strconv.FormatInt(int64(value_fix), 8), flags_fmt)
		case FORMAT_BIN:
			return fmt.Sprintf("0b%s%s", strconv.FormatInt(int64(value_fix), 2), flags_fmt)
		default:
			return fmt.Sprintf("%d%s", value_fix, flags_fmt)
		}
	}
	return value_fmt
}
func (this *ARG_INT16) Parse(ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	value_fix := int16(ptr)
	value_fmt := fmt.Sprintf("%d", value_fix)
	if this.FlagsParser != nil {
		flags_fmt := this.FlagsParser.Parse(int32(value_fix))
		switch this.FormatType {
		case FORMAT_NUM:
			return fmt.Sprintf("%d%s", value_fix, flags_fmt)
		case FORMAT_HEX_PURE:
			return fmt.Sprintf("%x%s", value_fix, flags_fmt)
		case FORMAT_HEX:
			return fmt.Sprintf("0x%x%s", value_fix, flags_fmt)
		case FORMAT_DEC:
			return fmt.Sprintf("%d%s", value_fix, flags_fmt)
		case FORMAT_OCT:
			return fmt.Sprintf("0o%03s%s", strconv.FormatInt(int64(value_fix), 8), flags_fmt)
		case FORMAT_BIN:
			return fmt.Sprintf("0b%s%s", strconv.FormatInt(int64(value_fix), 2), flags_fmt)
		default:
			return fmt.Sprintf("%d%s", value_fix, flags_fmt)
		}
	}
	return value_fmt
}
func (this *ARG_INT32) Parse(ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	value_fix := int32(ptr)
	value_fmt := fmt.Sprintf("%d", value_fix)
	if this.FlagsParser != nil {
		flags_fmt := this.FlagsParser.Parse(int32(value_fix))
		switch this.FormatType {
		case FORMAT_NUM:
			return fmt.Sprintf("%d%s", value_fix, flags_fmt)
		case FORMAT_HEX_PURE:
			return fmt.Sprintf("%x%s", value_fix, flags_fmt)
		case FORMAT_HEX:
			return fmt.Sprintf("0x%x%s", value_fix, flags_fmt)
		case FORMAT_DEC:
			return fmt.Sprintf("%d%s", value_fix, flags_fmt)
		case FORMAT_OCT:
			return fmt.Sprintf("0o%03s%s", strconv.FormatInt(int64(value_fix), 8), flags_fmt)
		case FORMAT_BIN:
			return fmt.Sprintf("0b%s%s", strconv.FormatInt(int64(value_fix), 2), flags_fmt)
		default:
			return fmt.Sprintf("%d%s", value_fix, flags_fmt)
		}
	}
	return value_fmt
}
func (this *ARG_INT64) Parse(ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	value_fix := int64(ptr)
	value_fmt := fmt.Sprintf("%d", value_fix)
	if this.FlagsParser != nil {
		flags_fmt := this.FlagsParser.Parse(int32(value_fix))
		switch this.FormatType {
		case FORMAT_NUM:
			return fmt.Sprintf("%d%s", value_fix, flags_fmt)
		case FORMAT_HEX_PURE:
			return fmt.Sprintf("%x%s", value_fix, flags_fmt)
		case FORMAT_HEX:
			return fmt.Sprintf("0x%x%s", value_fix, flags_fmt)
		case FORMAT_DEC:
			return fmt.Sprintf("%d%s", value_fix, flags_fmt)
		case FORMAT_OCT:
			return fmt.Sprintf("0o%03s%s", strconv.FormatInt(int64(value_fix), 8), flags_fmt)
		case FORMAT_BIN:
			return fmt.Sprintf("0b%s%s", strconv.FormatInt(int64(value_fix), 2), flags_fmt)
		default:
			return fmt.Sprintf("%d%s", value_fix, flags_fmt)
		}
	}
	return value_fmt
}
func (this *ARG_UINT8) Parse(ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	value_fix := uint8(ptr)
	value_fmt := fmt.Sprintf("%d", value_fix)
	if this.FlagsParser != nil {
		flags_fmt := this.FlagsParser.Parse(int32(value_fix))
		switch this.FormatType {
		case FORMAT_NUM:
			return fmt.Sprintf("%d%s", value_fix, flags_fmt)
		case FORMAT_HEX_PURE:
			return fmt.Sprintf("%x%s", value_fix, flags_fmt)
		case FORMAT_HEX:
			return fmt.Sprintf("0x%x%s", value_fix, flags_fmt)
		case FORMAT_DEC:
			return fmt.Sprintf("%d%s", value_fix, flags_fmt)
		case FORMAT_OCT:
			return fmt.Sprintf("0o%03s%s", strconv.FormatInt(int64(value_fix), 8), flags_fmt)
		case FORMAT_BIN:
			return fmt.Sprintf("0b%s%s", strconv.FormatInt(int64(value_fix), 2), flags_fmt)
		default:
			return fmt.Sprintf("%d%s", value_fix, flags_fmt)
		}
	}
	return value_fmt
}
func (this *ARG_UINT16) Parse(ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	value_fix := uint16(ptr)
	value_fmt := fmt.Sprintf("%d", value_fix)
	if this.FlagsParser != nil {
		flags_fmt := this.FlagsParser.Parse(int32(value_fix))
		switch this.FormatType {
		case FORMAT_NUM:
			return fmt.Sprintf("%d%s", value_fix, flags_fmt)
		case FORMAT_HEX_PURE:
			return fmt.Sprintf("%x%s", value_fix, flags_fmt)
		case FORMAT_HEX:
			return fmt.Sprintf("0x%x%s", value_fix, flags_fmt)
		case FORMAT_DEC:
			return fmt.Sprintf("%d%s", value_fix, flags_fmt)
		case FORMAT_OCT:
			return fmt.Sprintf("0o%03s%s", strconv.FormatInt(int64(value_fix), 8), flags_fmt)
		case FORMAT_BIN:
			return fmt.Sprintf("0b%s%s", strconv.FormatInt(int64(value_fix), 2), flags_fmt)
		default:
			return fmt.Sprintf("%d%s", value_fix, flags_fmt)
		}
	}
	return value_fmt
}
func (this *ARG_UINT32) Parse(ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	value_fix := uint32(ptr)
	value_fmt := fmt.Sprintf("%d", value_fix)
	if this.FlagsParser != nil {
		flags_fmt := this.FlagsParser.Parse(int32(value_fix))
		switch this.FormatType {
		case FORMAT_NUM:
			return fmt.Sprintf("%d%s", value_fix, flags_fmt)
		case FORMAT_HEX_PURE:
			return fmt.Sprintf("%x%s", value_fix, flags_fmt)
		case FORMAT_HEX:
			return fmt.Sprintf("0x%x%s", value_fix, flags_fmt)
		case FORMAT_DEC:
			return fmt.Sprintf("%d%s", value_fix, flags_fmt)
		case FORMAT_OCT:
			return fmt.Sprintf("0o%03s%s", strconv.FormatInt(int64(value_fix), 8), flags_fmt)
		case FORMAT_BIN:
			return fmt.Sprintf("0b%s%s", strconv.FormatInt(int64(value_fix), 2), flags_fmt)
		default:
			return fmt.Sprintf("%d%s", value_fix, flags_fmt)
		}
	}
	return value_fmt
}

func (this *ARG_UINT64) Parse(ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	value_fix := uint64(ptr)
	value_fmt := fmt.Sprintf("%d", value_fix)
	if this.FlagsParser != nil {
		flags_fmt := this.FlagsParser.Parse(int32(value_fix))
		switch this.FormatType {
		case FORMAT_NUM:
			return fmt.Sprintf("%d%s", value_fix, flags_fmt)
		case FORMAT_HEX_PURE:
			return fmt.Sprintf("%x%s", value_fix, flags_fmt)
		case FORMAT_HEX:
			return fmt.Sprintf("0x%x%s", value_fix, flags_fmt)
		case FORMAT_DEC:
			return fmt.Sprintf("%d%s", value_fix, flags_fmt)
		case FORMAT_OCT:
			return fmt.Sprintf("0o%03s%s", strconv.FormatInt(int64(value_fix), 8), flags_fmt)
		case FORMAT_BIN:
			return fmt.Sprintf("0b%s%s", strconv.FormatInt(int64(value_fix), 2), flags_fmt)
		default:
			return fmt.Sprintf("%d%s", value_fix, flags_fmt)
		}
	}
	return value_fmt
}

type ARG_STRUCT struct {
	ArgType
}

type ARG_ARRAY struct {
	ARG_STRUCT
	ArrayLen     uint32
	ArrayArgType IArgType
}

// func (this *ARG_STRUCT) Setup() {
// 	this.AddOp(SaveStruct(uint64(this.Size)))
// }

func (this *ARG_STRUCT) Clone() IArgType {
	p, ok := (this.ArgType.Clone()).(*ArgType)
	if !ok {
		panic("...")
	}
	return &ARG_STRUCT{*p}
}

func (this *ARG_STRUCT) Parse(ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	// if !parse_more {
	// 	return fmt.Sprintf("0x%x", ptr)
	// }
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
	Register(&ARG_PTR{}, "ptr", TYPE_POINTER, config.POINTER, uint32(unsafe.Sizeof(uint64(0))))
	Register(&ARG_INT{}, "int", TYPE_INT, config.INT, uint32(unsafe.Sizeof(int32(0))))
	Register(&ARG_UINT{}, "uint", TYPE_UINT, config.UINT, uint32(unsafe.Sizeof(uint32(0))))
	Register(&ARG_INT8{}, "int8", TYPE_INT8, config.INT8, uint32(unsafe.Sizeof(int8(0))))
	Register(&ARG_INT16{}, "int16", TYPE_INT16, config.INT16, uint32(unsafe.Sizeof(int16(0))))
	Register(&ARG_INT32{}, "int32", TYPE_INT32, config.INT32, uint32(unsafe.Sizeof(int32(0))))
	Register(&ARG_INT64{}, "int64", TYPE_INT64, config.INT64, uint32(unsafe.Sizeof(int64(0))))
	Register(&ARG_UINT8{}, "uint8", TYPE_UINT8, config.UINT8, uint32(unsafe.Sizeof(uint8(0))))
	Register(&ARG_UINT16{}, "uint16", TYPE_UINT16, config.UINT16, uint32(unsafe.Sizeof(uint16(0))))
	Register(&ARG_UINT32{}, "uint32", TYPE_UINT32, config.UINT32, uint32(unsafe.Sizeof(uint32(0))))
	Register(&ARG_UINT64{}, "uint64", TYPE_UINT64, config.UINT64, uint32(unsafe.Sizeof(uint64(0))))
	// 一些实际上是数字的类型 后续注意要区分架构
	// socklen_t aarch64 下是 uint32 aarch32 下是 int32
	RegisterAlias("socklen_t", "uint32")
	// size_t aarch64 下是 uint64 aarch32 下是 uint32
	RegisterAlias("size_t", "uint64")
	// ssize_t aarch64 下是 int64 aarch32 下是 int32
	RegisterAlias("ssize_t", "int64")

	Register(&ARG_STRUCT{}, "struct", TYPE_STRUCT, config.STRUCT, 0)
}
