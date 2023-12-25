package next

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
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
	// 先直接保存对应的数据 即 元素大小 * 元素个数
	at.AddOp(SaveStruct(uint64(p.GetSize() * array_len)))
	switch p.(type) {
	case *ARG_INT:
	case *ARG_INT32:
		// 对于数字类型不需要额外操作
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
