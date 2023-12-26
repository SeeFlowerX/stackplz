package next

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"stackplz/user/util"
	"strings"
)

type ARG_STRING_ARR struct {
	ArgType
}

func (this *ARG_STRING_ARR) Setup() {
	this.AddOp(OPC_SAVE_STRING_ARR)
}

func (this *ARG_STRING_ARR) Parse(ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	if !parse_more {
		return fmt.Sprintf("0x%x", ptr)
	}
	var arg Arg_str_arr
	if err := binary.Read(buf, binary.LittleEndian, &arg); err != nil {
		panic(err)
	}
	var str_arr []string
	for i := 0; i < int(arg.Count); i++ {
		var len uint32
		if err := binary.Read(buf, binary.LittleEndian, &len); err != nil {
			panic(err)
		}
		payload := make([]byte, len)
		if err := binary.Read(buf, binary.LittleEndian, &payload); err != nil {
			panic(err)
		}
		str_arr = append(str_arr, util.B2STrim(payload))
	}
	return fmt.Sprintf("0x%x[%s]", ptr, strings.Join(str_arr, ", "))
}

func init() {
	Register(&ARG_STRING_ARR{}, "strings", TYPE_STRING_ARR, MAX_BUF_READ_SIZE)
}
