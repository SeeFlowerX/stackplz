package config

import (
	"fmt"
	"stackplz/user/argtype"
)

type UprobeArgs struct {
	Index     uint32
	LibPath   string
	Name      string
	Symbol    string
	SymOffset uint64
	Offset    uint64
	ArgsStr   string
	PointArgs []*PointArg
}

func (this *UprobeArgs) GetConfig() UprobePointOpKeyConfig {
	config := UprobePointOpKeyConfig{}
	for _, point_arg := range this.PointArgs {
		config.AddPointArg(point_arg)
	}
	// this.DumpOpList("uprobe_"+this.Name, config.OpKeyList[:])
	return config
}

func (this *UprobeArgs) DumpOpList(tag string, op_list []uint32) {
	fmt.Printf("[DumpOpList] %s Name:%s Count:%d\n", tag, this.Name, len(op_list))
	for index, op_index := range op_list {
		if op_index == 0 {
			continue
		}
		fmt.Printf("idx:%3d op_key:%3d %s\n", index, op_index, argtype.OPM.GetOpInfo(op_index))
	}
}

// type UPointTypes struct {
// 	Count    uint32
// 	ArgTypes [MAX_POINT_ARG_COUNT]FilterArgType
// }

// func (this *UprobeArgs) GetConfig() UPointTypes {
// 	// 当前这样传递配置的方式比较耗时
// 	var point_arg_types [MAX_POINT_ARG_COUNT]FilterArgType
// 	for i := 0; i < MAX_POINT_ARG_COUNT; i++ {
// 		if i+1 > len(this.Args) {
// 			break
// 		}
// 		point_arg_types[i].PointFlag = this.Args[i].PointFlag
// 		point_arg_types[i].ArgType = this.Args[i].ArgType
// 	}
// 	config := UPointTypes{
// 		Count:    uint32(len(this.Args)),
// 		ArgTypes: point_arg_types,
// 	}
// 	return config
// }

func (this *UprobeArgs) String() string {
	if this.Symbol == "" {
		return fmt.Sprintf("[%s + 0x%x] %s", this.LibPath, this.Offset, this.ArgsStr)
	} else {
		return fmt.Sprintf("[%s]sym:%s off:0x%x %s", this.LibPath, this.Symbol, this.Offset, this.ArgsStr)
	}
}

// type UArgs = UprobeArgs
