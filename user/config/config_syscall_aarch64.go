package config

import (
	"fmt"
	"strings"
)

type PointConfig_C struct {
	OpCount     uint32
	OpIndexList [MAX_OP_COUNT]uint32
}

type OpKeyConfig struct {
	OpList []*OpConfig
}

func NewOpKeyConfig() *OpKeyConfig {
	v := &OpKeyConfig{}
	return v
}

func (this *OpKeyConfig) AddOp(op *OpConfig) {
	this.OpList = append(this.OpList, op)
}

type ArgOpConfig struct {
	ArgName string
	ArgType *OpArgType
}

func (this *ArgOpConfig) IsPtr() bool {
	// 是否配置为指针类型
	return strings.HasPrefix(this.ArgName, "*")
}

type PointArgsConfig struct {
	Nr           uint32
	Name         string
	Args         []*ArgOpConfig
	ArgsSysExit  *OpKeyConfig
	ArgsSysEnter *OpKeyConfig
}

func (this *PointArgsConfig) GetConfig() PointConfig_C {
	point := PointConfig_C{}
	point.OpCount = uint32(len(this.ArgsSysEnter.OpList))
	if int(point.OpCount) > len(point.OpIndexList) {
		panic(fmt.Sprintf("too many op for %s", this.Name))
	}
	for i, op := range this.ArgsSysEnter.OpList {
		point.OpIndexList[i] = op.Index
	}
	// fmt.Println("[GetConfig]", this.Name, point)
	return point
}

type SyscallPoints struct {
	points []PointArgsConfig
}

func (this *SyscallPoints) IsDup(nr uint32, name string) bool {
	is_dup := false
	for _, point := range this.points {
		if point.Nr == nr {
			is_dup = true
			break
		} else if point.Name == name {
			is_dup = true
			break
		}
	}
	return is_dup
}

func (this *SyscallPoints) Add(nr uint32, name string, args_config []*ArgOpConfig, exit_config, enter_config *OpKeyConfig) {
	point_config := PointArgsConfig{nr, name, args_config, exit_config, enter_config}
	this.points = append(this.points, point_config)
}

func (this *SyscallPoints) GetPointConfigByNR(nr uint32) *OpKeyConfig {
	for _, point := range this.points {
		if point.Nr == nr {
			return point.ArgsSysEnter
		}
	}
	panic(fmt.Sprintf("GetPointConfigByNR failed for nr %d", nr))
}

func (this *SyscallPoints) GetPointConfigByName(name string) *OpKeyConfig {
	for _, point := range this.points {
		if point.Name == name {
			return point.ArgsSysEnter
		}
	}
	panic(fmt.Sprintf("GetPointConfigByName failed for name %s", name))
}

func (this *SyscallPoints) GetPointByName(name string) *PointArgsConfig {
	for _, point := range this.points {
		if point.Name == name {
			return &point
		}
	}
	panic(fmt.Sprintf("GetPointByName failed for name %s", name))
}

func (this *SyscallPoints) GetPointByNR(nr uint32) *PointArgsConfig {
	for _, point := range this.points {
		if point.Nr == nr {
			return &point
		}
	}
	panic(fmt.Sprintf("GetPointByNR failed for nr:%d", nr))
}

func GetSyscallPointByName(name string) *PointArgsConfig {
	return aarch64_syscall_points.GetPointByName(name)
}

func GetSyscallPointByNR(nr uint32) *PointArgsConfig {
	return aarch64_syscall_points.GetPointByNR(nr)
}

const (
	OP_LIST_COMMON_START uint32 = 0x400
)

type OpKeyHelper struct {
	op_list              map[uint32]OpConfig
	reg_index_op_key_map map[int]uint32
}

func (this *OpKeyHelper) get_op_config(op_key uint32) OpConfig {
	for k, v := range this.op_list {
		if k == op_key {
			return v
		}
	}
	panic(fmt.Sprintf("get_op_config for key:%d not exists", op_key))
}

func (this *OpKeyHelper) get_default_op_key(op_code uint32) uint32 {
	for k, v := range this.op_list {
		if v.Code == op_code && v.Value == 0 {
			return k
		}
	}
	panic(fmt.Sprintf("default_op_key for code:%d not exists", op_code))
}

func (this *OpKeyHelper) get_op_key(opc OpConfig) uint32 {
	for k, v := range this.op_list {
		if v.Code == opc.Code && v.Value == opc.Value {
			return k
		}
	}
	next_op_key := OP_LIST_COMMON_START + uint32(len(this.op_list))
	this.op_list[next_op_key] = opc
	return next_op_key
}

func (this *OpKeyHelper) add_reg_index_op_config(reg_index int, op_key uint32) {
	this.reg_index_op_key_map[reg_index] = op_key
}

func (this *OpKeyHelper) get_reg_index_op_key(reg_index int) uint32 {
	return this.reg_index_op_key_map[reg_index]
}

func (this *OpKeyHelper) GetOpList() map[uint32]OpConfig {
	// 取出会被用到的 op
	// 根据 op_key 去重即可
	return this.op_list
}

func X(arg_name string, arg_type *OpArgType) *ArgOpConfig {
	config := ArgOpConfig{}
	config.ArgName = arg_name
	config.ArgType = arg_type
	return &config
}

var aarch64_syscall_points = SyscallPoints{}

func R(nr uint32, name string, configs ...*ArgOpConfig) {
	// 不可重复
	if aarch64_syscall_points.IsDup(nr, name) {
		panic(fmt.Sprintf("register duplicate for nr:%d name:%s", nr, name))
	}
	op_key_config := NewOpKeyConfig()
	// 合并多个参数的操作数
	for reg_index, config := range configs {

		op_key_config.AddOp(Add_READ_SAVE_REG(uint64(reg_index)))
		op_key_config.AddOp(OPC_MOVE_REG_VALUE)
		for _, op := range config.ArgType.OpList {
			op_key_config.AddOp(op)
		}
	}
	// 关联到syscall
	aarch64_syscall_points.Add(nr, name, configs, NewOpKeyConfig(), op_key_config)
}

func init() {

	// 对一些复杂结构体的读取配置进行补充

	// 以指定寄存器作为数据读取长度
	AT_BUFFER_X2 := BuildBufferRegIndex(REG_ARM64_X2)

	// 以指定寄存器作为数据读取次数
	AT_IOVEC_X2 := BuildIovecRegIndex(REG_ARM64_X2)

	R(56, "openat", X("dirfd", AT_INT32), X("pathname", AT_STRING), X("flags", AT_INT32), X("mode", AT_INT16))
	R(66, "writev", X("fd", AT_INT32), X("*iov", AT_IOVEC_X2), X("iovcnt", AT_INT32))
	R(203, "connect", X("sockfd", AT_INT32), X("addr", AT_SOCKADDR), X("addrlen", AT_INT32))
	R(206, "sendto", X("sockfd", AT_INT32), X("*buf", AT_BUFFER_X2), X("len", AT_INT32), X("flags", AT_INT32), X("addr", AT_INT32), X("addrlen", AT_INT32))
	R(211, "sendmsg", X("sockfd", AT_INT32), X("*msg", AT_MSGHDR), X("flags", AT_INT32))
}
