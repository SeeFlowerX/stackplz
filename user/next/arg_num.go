package next

import (
	"bytes"
	"fmt"
	"strconv"
	"unsafe"
)

type ARG_NUM struct {
	ArgType
	FormatType uint32
}

func (this *ARG_NUM) Setup() {

}

func (this *ARG_NUM) ParseFlags(flags int32) string {
	if this.FlagsParser != nil {
		return this.FlagsParser.Parse(flags)
	}
	return ""
}

func AttachFlagsParser(p IArgType, flags_parser *FlagsParser) IArgType {
	at := ARG_NUM{}
	at.Name = p.GetName()
	at.Alias = p.GetAlias()
	at.Size = p.GetSize()
	at.FlagsParser = flags_parser
	at.FormatType = at.FlagsParser.FormatType
	switch p.(type) {
	case *ARG_PTR:
		return &ARG_PTR{at}
	case *ARG_INT:
		return &ARG_INT{at}
	case *ARG_UINT:
		return &ARG_UINT{at}
	case *ARG_INT8:
		return &ARG_INT8{at}
	case *ARG_INT16:
		return &ARG_INT16{at}
	case *ARG_INT32:
		return &ARG_INT32{at}
	case *ARG_INT64:
		return &ARG_INT64{at}
	case *ARG_UINT8:
		return &ARG_UINT8{at}
	case *ARG_UINT16:
		return &ARG_UINT16{at}
	case *ARG_UINT32:
		return &ARG_UINT32{at}
	case *ARG_UINT64:
		return &ARG_UINT64{at}
	}
	return &at
}

type ARG_PTR struct {
	ARG_NUM
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
	return fmt.Sprintf("0x%x", ptr)
}
func (this *ARG_INT) Parse(ptr uint64, buf *bytes.Buffer, parse_more bool) string {
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
func (this *ARG_UINT) Parse(ptr uint64, buf *bytes.Buffer, parse_more bool) string {
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

func init() {
	Register(&ARG_PTR{}, "ptr", TYPE_POINTER, uint32(unsafe.Sizeof(uint64(0))))
	Register(&ARG_INT{}, "int", TYPE_INT, uint32(unsafe.Sizeof(int32(0))))
	Register(&ARG_UINT{}, "uint", TYPE_UINT, uint32(unsafe.Sizeof(uint32(0))))
	Register(&ARG_INT8{}, "int8", TYPE_INT8, uint32(unsafe.Sizeof(int8(0))))
	Register(&ARG_INT16{}, "int16", TYPE_INT16, uint32(unsafe.Sizeof(int16(0))))
	Register(&ARG_INT32{}, "int32", TYPE_INT32, uint32(unsafe.Sizeof(int32(0))))
	Register(&ARG_INT64{}, "int64", TYPE_INT64, uint32(unsafe.Sizeof(int64(0))))
	Register(&ARG_UINT8{}, "uint8", TYPE_UINT8, uint32(unsafe.Sizeof(uint8(0))))
	Register(&ARG_UINT16{}, "uint16", TYPE_UINT16, uint32(unsafe.Sizeof(uint16(0))))
	Register(&ARG_UINT32{}, "uint32", TYPE_UINT32, uint32(unsafe.Sizeof(uint32(0))))
	Register(&ARG_UINT64{}, "uint64", TYPE_UINT64, uint32(unsafe.Sizeof(uint64(0))))
	// 一些实际上是数字的类型 后续注意要区分架构
	// socklen_t aarch64 下是 uint32 aarch32 下是 int32
	RegisterAlias("socklen_t", "uint32")
	// size_t aarch64 下是 uint64 aarch32 下是 uint32
	RegisterAlias("size_t", "uint64")
	// ssize_t aarch64 下是 int64 aarch32 下是 int32
	RegisterAlias("ssize_t", "int64")
}
