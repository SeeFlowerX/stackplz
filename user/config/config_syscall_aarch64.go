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

	// 读取 iov 注意 OPA_IOV 第一步会执行 OPC_SAVE_STRUCT
	// 将 op_ctx->read_addr 指向 iovec->iov_len
	// OPA_IOV.AddOp(OPC_ADD_OFFSET, 8)
	// // 读取 iovec->iov_len
	// OPA_IOV.AddOpC(OP_READ_POINTER)
	// // 设置 op_ctx->read_len 为默认的单次最大读取长度
	// OPA_IOV.AddOp(OPC_SET_READ_LEN, uint64(MAX_BUF_READ_SIZE))
	// // 修正 op_ctx->read_len
	// OPA_IOV.AddOpC(OP_SET_READ_LEN_POINTER_VALUE)
	// // 将 op_ctx->read_addr 重新指向 iovec 起始处
	// OPA_IOV.AddOp(OPC_SUB_OFFSET, 8)
	// // 读取 iovec->iov_base
	// OPA_IOV.AddOpC(OP_READ_POINTER)
	// // 转移 iovec->iov_base 到 op_ctx->read_addr
	// OPA_IOV.AddOpC(OP_MOVE_POINTER_VALUE)
	// // 读取 op_ctx->read_addr 处 op_ctx->read_len 长度的数据
	// OPA_IOV.AddOpC(OP_SAVE_STRUCT)

	// // 将 op_ctx->read_addr 保存到 op_ctx->tmp_value 也就是 msghdr 的地址
	// OPA_MSGHDR.AddOpC(OP_SET_TMP_VALUE)
	// // 将 op_ctx->read_addr 指向 msghdr->controllen
	// OPA_MSGHDR.AddOp(OPC_ADD_OFFSET, 8+4+4+8+8+8)
	// // 读取 msghdr->controllen
	// OPA_MSGHDR.AddOpC(OP_READ_POINTER)
	// // 设置 op_ctx->read_len 为默认的单次最大读取长度
	// OPA_MSGHDR.AddOp(OPC_SET_READ_LEN, uint64(MAX_BUF_READ_SIZE))
	// // 修正 op_ctx->read_len
	// OPA_MSGHDR.AddOpC(OP_SET_READ_LEN_POINTER_VALUE)
	// // 将 op_ctx->read_addr 指向 msghdr->control 起始处
	// OPA_MSGHDR.AddOp(OPC_SUB_OFFSET, 8)
	// // 读取 msghdr->control
	// OPA_MSGHDR.AddOpC(OP_READ_POINTER)
	// // 转移 msghdr->control 到 op_ctx->read_addr
	// OPA_MSGHDR.AddOpC(OP_MOVE_POINTER_VALUE)
	// // 读取 op_ctx->read_addr 处 op_ctx->read_len 长度的数据
	// OPA_MSGHDR.AddOpC(OP_SAVE_STRUCT)
	// // 恢复 op_ctx->tmp_value 也就是 op_ctx->read_addr 重新指向 msghdr
	// OPA_MSGHDR.AddOpC(OP_MOVE_TMP_VALUE)

	// // 将 op_ctx->read_addr 指向 msghdr->iovlen
	// OPA_MSGHDR.AddOp(OPC_ADD_OFFSET, 8+4+4+8)
	// // 读取 msghdr->iovlen
	// OPA_MSGHDR.AddOpC(OP_READ_POINTER)
	// // 将 iovlen 设置为循环次数上限
	// OPA_MSGHDR.AddOpC(OP_SET_BREAK_COUNT_POINTER_VALUE)
	// // 将读取地址指向 msghdr->iov
	// OPA_MSGHDR.AddOp(OPC_SUB_OFFSET, 8)
	// // 读取 msghdr->iov 指针
	// OPA_MSGHDR.AddOpC(OP_READ_POINTER)
	// // 将 op_ctx->read_addr 指向 msghdr->iov 指针
	// OPA_MSGHDR.AddOpC(OP_MOVE_POINTER_VALUE)
	// // 读取 msghdr->iov 最多读取 6 次 最少 msghdr->iovlen 次
	// for i := 0; i < 6; i++ {
	// 	OPA_MSGHDR.AddOp(OPC_FOR_BREAK, uint64(i))
	// 	// 保存 iov 指针
	// 	OPA_MSGHDR.AddOpC(OP_SAVE_ADDR)
	// 	// 将读取地址放一份到临时变量中
	// 	OPA_MSGHDR.AddOpC(OP_SET_TMP_VALUE)
	// 	// 读取 iov 数据
	// 	OPA_MSGHDR.AddOpA(OPA_IOV)
	// 	// 恢复临时变量结果到 读取地址
	// 	OPA_MSGHDR.AddOpC(OP_MOVE_TMP_VALUE)
	// 	// 将 读取地址 偏移到下一个 iov 指针处
	// 	OPA_MSGHDR.AddOp(OPC_ADD_OFFSET, 16)
	// }
	// OPA_MSGHDR.AddOpC(OP_RESET_BREAK)

	// 以指定寄存器作为数据读取长度
	AT_BUFFER_X2 := Add_READ_BUFFER_REG(REG_ARM64_X2)

	// 以指定寄存器作为数据读取次数
	AT_IOVEC_X2 := Add_REPEAT_READ_REG_VALUE(REG_ARM64_X2)

	R(56, "openat", X("dirfd", AT_INT32), X("pathname", AT_STRING), X("flags", AT_INT32), X("mode", AT_INT16))
	R(66, "writev", X("fd", AT_INT32), X("*iov", AT_IOVEC_X2), X("iovcnt", AT_INT32))
	R(206, "sendto", X("sockfd", AT_INT32), X("*buf", AT_BUFFER_X2), X("len", AT_INT32), X("flags", AT_INT32))

	// R(211, "sendmsg", X("sockfd", OPA_INT32), X("*msg", OPA_MSGHDR), X("flags", OPA_INT32))
}
