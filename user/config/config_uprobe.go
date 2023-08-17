package config

import (
	"fmt"
)

type UprobeArgs struct {
	Index     uint32
	LibPath   string
	Symbol    string
	SymOffset uint64
	Offset    uint64
	ArgsStr   string
	PointArgs
}

type UPointTypes struct {
	Count    uint32
	ArgTypes [MAX_POINT_ARG_COUNT]FilterArgType
}

func (this *UprobeArgs) GetConfig() *UPointTypes {
	// 当前这样传递配置的方式比较耗时
	var point_arg_types [MAX_POINT_ARG_COUNT]FilterArgType
	for i := 0; i < MAX_POINT_ARG_COUNT; i++ {
		if i+1 > len(this.Args) {
			break
		}
		point_arg_types[i].ReadFlag = this.Args[i].ReadFlag
		point_arg_types[i].ArgType = this.Args[i].ArgType
	}
	config := &UPointTypes{
		Count:    uint32(len(this.Args)),
		ArgTypes: point_arg_types,
	}
	return config
}

func (this *UprobeArgs) String() string {
	if this.Symbol == "" {
		return fmt.Sprintf("[%s + 0x%x] %s", this.LibPath, this.Offset, this.ArgsStr)
	} else {
		return fmt.Sprintf("[%s]sym:%s off:0x%x %s", this.LibPath, this.Symbol, this.Offset, this.ArgsStr)
	}
}

type UArgs = UprobeArgs
