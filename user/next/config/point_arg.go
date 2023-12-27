package config

import (
	"bytes"
	"stackplz/user/next/argtype"
	. "stackplz/user/next/common"
)

type PointArg struct {
	Name      string
	RegIndex  uint32
	TypeIndex uint32
	OpList    []uint32
	PointType uint32
	GroupType uint32
}

func (this *PointArg) SetRegIndex(reg_index uint32) {
	this.RegIndex = reg_index
}

func (this *PointArg) SetGroupType(group_type uint32) {
	this.GroupType = group_type
}

func (this *PointArg) Parse(ptr uint64, buf *bytes.Buffer, point_type uint32) string {
	parse_more := false
	if this.PointType == EBPF_SYS_ALL || this.PointType == point_type {
		parse_more = true
	}
	return argtype.GetArgType(this.RegIndex).Parse(ptr, buf, parse_more)
}

// func (this *PointArg) BuildOpList(read_full bool) {
// 	// this.OpList = append(this.OpList, Add_READ_SAVE_REG(uint64(this.RegIndex)).Index)
// 	// this.OpList = append(this.OpList, OPC_MOVE_REG_VALUE.Index)
// 	if read_full {
// 		for _, op_key := range this.Type.GetOpList() {
// 			this.OpList = append(this.OpList, op_key)
// 		}
// 	}
// }

func (this *PointArg) GetOpList() []uint32 {
	this.OpList = append(this.OpList, argtype.Add_READ_SAVE_REG(uint64(this.RegIndex)).Index)
	this.OpList = append(this.OpList, argtype.OPC_MOVE_REG_VALUE.Index)
	if this.PointType == EBPF_SYS_ALL || this.PointType == this.GroupType {
		for _, op_key := range argtype.GetOpKeyList(this.TypeIndex) {
			this.OpList = append(this.OpList, op_key)
		}
	}
	return this.OpList
}

func (this *PointArg) Clone() *PointArg {
	p := PointArg{}
	p.Name = this.Name
	p.RegIndex = this.RegIndex
	p.TypeIndex = this.TypeIndex
	p.OpList = append(p.OpList, this.OpList...)
	p.PointType = this.PointType
	return &p
}

func NewPointArg(arg_name string, type_index, point_type uint32) *PointArg {
	point_arg := PointArg{}
	point_arg.Name = arg_name
	point_arg.RegIndex = REG_ARM64_MAX
	point_arg.TypeIndex = type_index
	point_arg.PointType = point_type
	return &point_arg
}

func A(arg_name string, type_index uint32) *PointArg {
	return NewPointArg(arg_name, type_index, EBPF_SYS_ENTER)
}
func B(arg_name string, type_index uint32) *PointArg {
	return NewPointArg(arg_name, type_index, EBPF_SYS_EXIT)
}
func C(arg_name string, type_index uint32) *PointArg {
	return NewPointArg(arg_name, type_index, EBPF_SYS_ALL)
}

// func A(arg_name string, arg_type argtype.IArgType) *PointArg {
// 	return NewPointArg(arg_name, arg_type, EBPF_SYS_ENTER)
// }

// func B(arg_name string, arg_type argtype.IArgType) *PointArg {
// 	return NewPointArg(arg_name, arg_type, EBPF_SYS_EXIT)
// }

// func C(arg_name string, arg_type argtype.IArgType) *PointArg {
// 	return NewPointArg(arg_name, arg_type, EBPF_SYS_ALL)
// }
