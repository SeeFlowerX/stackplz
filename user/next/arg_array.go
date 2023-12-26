package next

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"stackplz/user/util"
	"strings"
	"unsafe"
)

type ARG_ARRAY struct {
	ARG_STRUCT
	ArrayLen     uint32
	ArrayArgType IArgType
}

func (this *ARG_ARRAY) Setup() {
}

func (this *ARG_ARRAY) SetupArray(p IArgType, array_len uint32) IArgType {
	at := ARG_ARRAY{}
	at.Name = fmt.Sprintf("%s_%s_%d", this.Name, p.GetName(), array_len)
	at.Alias = this.Alias
	at.Size = uint32(p.GetSize() * array_len)
	at.ArrayLen = array_len
	at.ArrayArgType = p

	switch p.(type) {
	case *ARG_STRING:
		// 直接当作指针处理
		at.Size = 8 * array_len
		at.AddOp(SaveStruct(uint64(8 * array_len)))
		break
	default:
		// 直接保存对应的数据 即 元素大小 * 元素个数
		at.AddOp(SaveStruct(uint64(p.GetSize() * array_len)))
	}

	switch p.(type) {
	case *ARG_STRING:
		// 继续改进... 可以添加一个条件 比如被读取地址为0结束
		at.AddOp(OPC_SET_BREAK_COUNT.NewValue(uint64(array_len)))
		at.AddOp(OPC_FOR_BREAK)
		at.AddOp(OPC_SET_TMP_VALUE)
		at.AddOp(OPC_READ_POINTER)
		at.AddOp(OPC_MOVE_POINTER_VALUE)
		at.AddOp(OPC_SAVE_STRING)
		at.AddOp(OPC_MOVE_TMP_VALUE)
		at.AddOp(OPC_ADD_OFFSET.NewValue(uint64(unsafe.Sizeof(8))))
		at.AddOp(OPC_FOR_BREAK)
		break
	}

	return &at
}

func (this *ARG_ARRAY) Parse(ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	if !parse_more {
		return fmt.Sprintf("0x%x", ptr)
	}
	if this.GetStructLen(buf) == 0 {
		return fmt.Sprintf("0x%x[]", ptr)
	}
	var results []string
	switch this.ArrayArgType.(type) {
	case *ARG_STRING:
		var arg []uint64 = make([]uint64, this.ArrayLen)
		if err := binary.Read(buf, binary.LittleEndian, &arg); err != nil {
			panic(err)
		}
		for i := 0; i < int(this.ArrayLen); i++ {
			var arg_str Arg_str
			if err := binary.Read(buf, binary.LittleEndian, &arg_str); err != nil {
				panic(err)
			}
			payload := make([]byte, arg_str.Len)
			if err := binary.Read(buf, binary.LittleEndian, &payload); err != nil {
				panic(err)
			}
			result := fmt.Sprintf("0x%x(%s)", arg[i], util.B2STrim(payload))
			results = append(results, result)
		}
	case *ARG_INT:
		var arg []int32 = make([]int32, this.ArrayLen)
		if err := binary.Read(buf, binary.LittleEndian, &arg); err != nil {
			panic(err)
		}
		for _, v := range arg {
			result := this.ArrayArgType.Parse(uint64(v), buf, parse_more)
			results = append(results, result)
		}
		break
	case *ARG_UINT:
		var arg []uint32 = make([]uint32, this.ArrayLen)
		if err := binary.Read(buf, binary.LittleEndian, &arg); err != nil {
			panic(err)
		}
		for _, v := range arg {
			result := this.ArrayArgType.Parse(uint64(v), buf, parse_more)
			results = append(results, result)
		}
		break
	case *ARG_INT32:
		var arg []int32 = make([]int32, this.ArrayLen)
		if err := binary.Read(buf, binary.LittleEndian, &arg); err != nil {
			panic(err)
		}
		for _, v := range arg {
			result := this.ArrayArgType.Parse(uint64(v), buf, parse_more)
			results = append(results, result)
		}
		break
		// case *ARG_IOVEC:
		// 	// 对于复杂的类型 这里合并其操作
		// 	at, ok := (p).(*ARG_IOVEC)
		// 	if !ok {
		// 		panic("...")
		// 	}
		// 	this.AddOpList(at)
		// 	break
	}
	return fmt.Sprintf("0x%x[%s]", ptr, strings.Join(results, ", "))
}

func ReadAsArray(p IArgType, array_len uint32) IArgType {
	at, ok := GetArgType("array").(*ARG_ARRAY)
	if !ok {
		panic("...")
	}
	return at.SetupArray(p, array_len)
}

func init() {
	Register(&ARG_ARRAY{}, "array", TYPE_ARRAY, 0)
}
