package config

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"stackplz/user/argtype"
	"strings"
)

type SyscallPoint struct {
	Nr             uint32
	Name           string
	EnterPointArgs []*PointArg
	ExitPointArgs  []*PointArg
}

func (this *SyscallPoint) DumpOpList(tag string, op_list []uint32) {
	fmt.Printf("[DumpOpList] %s Name:%s Count:%d\n", tag, this.Name, len(op_list))
	for index, op_index := range op_list {
		if op_index == 0 {
			continue
		}
		fmt.Printf("idx:%3d op_key:%3d %s\n", index, op_index, argtype.OPM.GetOpInfo(op_index))
	}
}

func (this *SyscallPoint) GetEnterConfig() SyscallPointOpKeyConfig {
	config := SyscallPointOpKeyConfig{}
	config.Signal = 0
	for _, point_arg := range this.EnterPointArgs {
		config.AddPointArg(point_arg)
	}
	// this.DumpOpList("enter", config.OpKeyList[:])
	return config
}

func (this *SyscallPoint) GetExitConfig() SyscallPointOpKeyConfig {
	config := SyscallPointOpKeyConfig{}
	config.Signal = 0
	for _, point_arg := range this.ExitPointArgs {
		config.AddPointArg(point_arg)
	}
	// this.DumpOpList("exit", config.OpKeyList[:])
	return config
}

func (this *SyscallPoint) ParseEnterPoint(buf *bytes.Buffer) string {
	var results []string
	for _, point_arg := range this.EnterPointArgs {
		var ptr argtype.Arg_reg
		if err := binary.Read(buf, binary.LittleEndian, &ptr); err != nil {
			panic(err)
		}
		arg_fmt := point_arg.Parse(ptr.Address, buf, EBPF_SYS_ENTER)
		results = append(results, fmt.Sprintf("%s=%s", point_arg.Name, arg_fmt))
	}
	return "(" + strings.Join(results, ", ") + ")"
}

func (this *SyscallPoint) ParsePointJson(buf *bytes.Buffer, point_type uint32) any {
	var results []any
	var point_args []*PointArg
	if point_type == EBPF_SYS_ENTER {
		point_args = this.EnterPointArgs
	} else {
		point_args = this.ExitPointArgs
	}
	for _, point_arg := range point_args {
		var ptr argtype.Arg_reg
		if err := binary.Read(buf, binary.LittleEndian, &ptr); err != nil {
			panic(err)
		}
		type ArgRegAlias argtype.Arg_reg
		type PointArgAlias PointArg
		result := &struct {
			*PointArgAlias
			*ArgRegAlias
			Address  string `json:"reg_value"`
			ArgType  string `json:"arg_type"`
			ArgValue any    `json:"arg_value"`
		}{
			PointArgAlias: (*PointArgAlias)(point_arg),
			ArgRegAlias:   (*ArgRegAlias)(&ptr),
			Address:       fmt.Sprintf("0x%x", ptr.Address),
			ArgType:       point_arg.GetTypeName(),
			ArgValue:      point_arg.ParseJson(ptr.Address, buf, point_type),
		}
		results = append(results, result)
	}
	return &results

}

func (this *SyscallPoint) ParseExitPoint(buf *bytes.Buffer) string {
	var results []string
	for _, point_arg := range this.ExitPointArgs {
		var ptr argtype.Arg_reg
		if err := binary.Read(buf, binary.LittleEndian, &ptr); err != nil {
			panic(err)
		}
		arg_fmt := point_arg.Parse(ptr.Address, buf, EBPF_SYS_EXIT)
		results = append(results, fmt.Sprintf("%s=%s", point_arg.Name, arg_fmt))
	}
	return "(" + strings.Join(results, ", ") + ")"
}
