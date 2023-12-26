package next

import (
	"stackplz/user/next/argtype"
	"stackplz/user/next/config"
)

type PointArg struct {
	Name      string
	RegIndex  uint32
	Type      argtype.IArgType
	TypeIndex uint32
	OpList    []uint32
	PointType uint32
}

func (this *PointArg) SetRegIndex(reg_index uint32) {
	this.RegIndex = reg_index
}

func (this *PointArg) BuildOpList(read_full bool) {
	// this.OpList = append(this.OpList, Add_READ_SAVE_REG(uint64(this.RegIndex)).Index)
	// this.OpList = append(this.OpList, OPC_MOVE_REG_VALUE.Index)
	if read_full {
		for _, op_key := range this.Type.GetOpList() {
			this.OpList = append(this.OpList, op_key)
		}
	}
}

func (this *PointArg) GetOpList() []uint32 {
	return this.OpList
}

func (this *PointArg) Clone() *PointArg {
	p := PointArg{}
	p.Name = this.Name
	p.RegIndex = this.RegIndex
	p.Type = this.Type
	p.OpList = append(p.OpList, this.OpList...)
	p.PointType = this.PointType
	return &p
}

func NewPointArg(arg_name string, arg_type argtype.IArgType, point_type uint32) *PointArg {
	point_arg := PointArg{}
	point_arg.Name = arg_name
	point_arg.RegIndex = config.REG_ARM64_MAX
	point_arg.Type = arg_type
	point_arg.PointType = point_type
	return &point_arg
}

func A(arg_name string, arg_type argtype.IArgType) *PointArg {
	return NewPointArg(arg_name, arg_type, EBPF_SYS_ENTER)
}

func B(arg_name string, arg_type argtype.IArgType) *PointArg {
	return NewPointArg(arg_name, arg_type, EBPF_SYS_EXIT)
}

func C(arg_name string, arg_type argtype.IArgType) *PointArg {
	return NewPointArg(arg_name, arg_type, EBPF_SYS_ALL)
}
