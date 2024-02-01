package config

import (
	"bytes"
	"stackplz/user/argtype"
	. "stackplz/user/common"
)

type PointArg struct {
	Name            string   `json:"arg_name"`
	RegIndex        uint32   `json:"reg_index"`
	TypeIndex       uint32   `json:"-"`
	ExtraOpList     []uint32 `json:"-"`
	FilterIndexList []uint32 `json:"-"`
	PointType       uint32   `json:"-"`
	GroupType       uint32   `json:"-"`
}

func (this *PointArg) GetTypeName() string {
	return argtype.GetArgType(this.TypeIndex).GetName()
}

func (this *PointArg) SetRegIndex(reg_index uint32) {
	this.RegIndex = reg_index
}

func (this *PointArg) SetTypeIndex(type_index uint32) {
	this.TypeIndex = type_index
}

func (this *PointArg) SetFlagsFormat(format string) {
	var p argtype.IArgType
	switch format {
	case "inotify_flags":
		p = argtype.NewNumFlags(this.TypeIndex, argtype.InotifyFlagsConfig)
	case "access_flags":
		p = argtype.NewNumFlags(this.TypeIndex, argtype.AccessFlagsConfig)
	case "mmap_flags":
		p = argtype.NewNumFlags(this.TypeIndex, argtype.MMapFlagsConfig)
	case "mremap_flags":
		p = argtype.NewNumFlags(this.TypeIndex, argtype.MremapFlagsConfig)
	case "file_flags":
		p = argtype.NewNumFlags(this.TypeIndex, argtype.FileFlagsConfig)
	case "prot_flags":
		p = argtype.NewNumFlags(this.TypeIndex, argtype.ProtFlagsConfig)
	case "fcntl_flags":
		p = argtype.NewNumFlags(this.TypeIndex, argtype.FcntlFlagsConfig)
	case "statx_flags":
		p = argtype.NewNumFlags(this.TypeIndex, argtype.StatxFlagsConfig)
	case "unlink_flags":
		p = argtype.NewNumFlags(this.TypeIndex, argtype.UnlinkFlagsConfig)
	case "msg_flags":
		p = argtype.NewNumFlags(this.TypeIndex, argtype.MsgFlagsConfig)
	case "socket_flags":
		p = argtype.NewNumFlags(this.TypeIndex, argtype.SocketFlagsConfig)
	case "perm_flags":
		p = argtype.NewNumFlags(this.TypeIndex, argtype.PermissionFlagsConfig)
	default:
		panic("...")
	}
	this.TypeIndex = p.GetTypeIndex()
}

func (this *PointArg) SetTypeByName(name string) {
	this.TypeIndex = argtype.GetArgTypeByName(name).GetTypeIndex()
}

func (this *PointArg) SetHexFormat() {
	at := argtype.GetArgType(this.TypeIndex)
	if at.GetParentIndex() == ARRAY {
		return
	}
	this.TypeIndex = argtype.R_NUM_HEX(this.TypeIndex).GetTypeIndex()
}

func (this *PointArg) ToPointerType() {
	// 暂时仅限数字类型
	at := argtype.GetArgType(this.TypeIndex)
	this.TypeIndex = argtype.R_POINTER(at, true).GetTypeIndex()
}

func (this *PointArg) AddExtraOp(op *argtype.OpConfig) {
	// fmt.Println("op info:", op.Index, argtype.OPM.GetOpInfo(op.Index))
	this.ExtraOpList = append(this.ExtraOpList, op.Index)
}

func (this *PointArg) AddFilterIndex(filter_index uint32) {
	this.FilterIndexList = append(this.FilterIndexList, filter_index)
}

func (this *PointArg) SetGroupType(group_type uint32) {
	this.GroupType = group_type
}

func (this *PointArg) SetPointType(point_type uint32) {
	this.PointType = point_type
}

func (this *PointArg) ReadMore() bool {
	return this.PointType == EBPF_SYS_ALL || this.PointType == this.GroupType
}

func (this *PointArg) Parse(ptr uint64, buf *bytes.Buffer, point_type uint32) string {
	parse_more := false
	if this.PointType == EBPF_SYS_ALL || this.PointType == point_type {
		parse_more = true
	}
	return argtype.GetArgType(this.TypeIndex).Parse(ptr, buf, parse_more)
}

func (this *PointArg) ParseJson(ptr uint64, buf *bytes.Buffer, point_type uint32) any {
	parse_more := false
	if this.PointType == EBPF_SYS_ALL || this.PointType == point_type {
		parse_more = true
	}
	return argtype.GetArgType(this.TypeIndex).ParseJson(ptr, buf, parse_more)
}

func (this *PointArg) GetOpList() []uint32 {
	// op_list 使用时生成即可
	op_list := []uint32{}
	// sys exit 取出的返回值要特殊处理 这里没用实际的操作
	if this.RegIndex == REG_ARM64_MAX {
		return op_list
	}
	if len(this.ExtraOpList) > 0 {
		// 类型的最终读取地址 由 ExtraOpList 提供 记得读取之前要保存下地址
		op_list = append(op_list, this.ExtraOpList...)
	} else {
		op_list = append(op_list, argtype.Add_READ_SAVE_REG(uint64(this.RegIndex)).Index)
		op_list = append(op_list, argtype.OPC_MOVE_REG_VALUE.Index)
	}

	if this.TypeIndex != STRING && this.TypeIndex != STD_STRING {
		for _, v := range this.FilterIndexList {
			filter_op := argtype.OPC_FILTER_VALUE.NewValue(uint64(v))
			op_list = append(op_list, filter_op.Index)
		}
	}

	if this.ReadMore() {
		for _, op_key := range argtype.GetOpKeyList(this.TypeIndex) {
			op_list = append(op_list, op_key)
		}
		if this.TypeIndex == STRING || this.TypeIndex == STD_STRING {
			for _, v := range this.FilterIndexList {
				filter_op := argtype.OPC_FILTER_STRING.NewValue(uint64(v))
				op_list = append(op_list, filter_op.Index)
			}
		} else if this.IsBuffer() {
			for _, v := range this.FilterIndexList {
				filter_op := argtype.OPC_FILTER_BUFFER.NewValue(uint64(v))
				op_list = append(op_list, filter_op.Index)
			}
		}
	}
	return op_list
}

func (this *PointArg) IsBuffer() bool {
	return argtype.GetArgType(this.TypeIndex).GetParentIndex() == BUFFER
}

func (this *PointArg) Clone() *PointArg {
	p := PointArg{}
	p.Name = this.Name
	p.RegIndex = this.RegIndex
	p.TypeIndex = this.TypeIndex
	p.PointType = this.PointType
	p.FilterIndexList = this.FilterIndexList
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

func NewSyscallPointArg(arg_name string, type_index, reg_index, point_type uint32) *PointArg {
	point_arg := PointArg{}
	point_arg.Name = arg_name
	point_arg.RegIndex = reg_index
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

func NewUprobePointArg(arg_name string, type_index, reg_index uint32) *PointArg {
	point_arg := PointArg{}
	point_arg.Name = arg_name
	point_arg.RegIndex = reg_index
	point_arg.TypeIndex = type_index
	point_arg.PointType = EBPF_UPROBE_ENTER
	return &point_arg
}
