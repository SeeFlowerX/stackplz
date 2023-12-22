package config

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

type OpConfig struct {
	Code  uint32
	Value uint64
}

func (this *OpConfig) NewValue(value uint64) OpConfig {
	oc := this.Clone()
	oc.Value = value
	return oc
}

func (this *OpConfig) Clone() OpConfig {
	oc := OpConfig{}
	oc.Code = this.Code
	oc.Value = this.Value
	return oc
}

type OpKeyConfig struct {
	OpCount   uint32
	OpKeyList [MAX_OP_COUNT]uint32
}

func NewOpKeyConfig() OpKeyConfig {
	v := OpKeyConfig{}
	for i := 0; i < len(v.OpKeyList); i++ {
		v.OpKeyList[i] = op_key_helper.get_op_key(OPC_SKIP)
	}
	return v
}

func (this *OpKeyConfig) AddOpK(op_key uint32) {
	if int(this.OpCount) < len(this.OpKeyList) {
		this.OpKeyList[this.OpCount] = op_key
		this.OpCount++
	} else {
		panic(fmt.Sprintf("add op_key[%d] failed, max op count %d", op_key, len(this.OpKeyList)))
	}
}

type ArgOpConfig struct {
	ArgName   string
	AliasType uint32
	ArgValue  string
	OpKeyList []uint32
}

func (this *ArgOpConfig) IsPtr() bool {
	// 是否配置为指针类型
	return strings.HasPrefix(this.ArgName, "*")
}

type PointArgsConfig struct {
	Nr           uint32
	Name         string
	Args         []*ArgOpConfig
	ArgsSysExit  OpKeyConfig
	ArgsSysEnter OpKeyConfig
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

func (this *SyscallPoints) Add(nr uint32, name string, args_config []*ArgOpConfig, exit_config, enter_config OpKeyConfig) {
	point_config := PointArgsConfig{nr, name, args_config, exit_config, enter_config}
	this.points = append(this.points, point_config)
}

func (this *SyscallPoints) GetPointConfigByNR(nr uint32) *OpKeyConfig {
	for _, point := range this.points {
		if point.Nr == nr {
			return &point.ArgsSysEnter
		}
	}
	panic(fmt.Sprintf("GetPointConfigByNR failed for nr %d", nr))
}

func (this *SyscallPoints) GetPointConfigByName(name string) *OpKeyConfig {
	for _, point := range this.points {
		if point.Name == name {
			return &point.ArgsSysEnter
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

// operation code enum
const (
	OP_SKIP uint32 = iota + 233
	OP_RESET_CTX
	OP_SET_REG_INDEX
	OP_SET_READ_LEN
	OP_SET_READ_LEN_REG_VALUE
	OP_SET_READ_LEN_POINTER_VALUE
	OP_SET_READ_COUNT
	OP_ADD_OFFSET
	OP_SUB_OFFSET
	OP_MOVE_REG_VALUE
	OP_MOVE_POINTER_VALUE
	OP_MOVE_TMP_VALUE
	OP_SET_TMP_VALUE
	OP_SET_BREAK_COUNT_REG_VALUE
	OP_SET_BREAK_COUNT_POINTER_VALUE
	OP_SAVE_ADDR
	OP_READ_REG
	OP_SAVE_REG
	OP_READ_POINTER
	OP_SAVE_POINTER
	OP_READ_STRUCT
	OP_SAVE_STRUCT
	OP_READ_STRING
	OP_SAVE_STRING
	OP_FOR_BREAK
	OP_RESET_BREAK
)

var OpMap map[uint32]string = map[uint32]string{
	OP_SKIP:                          "OP_SKIP",
	OP_RESET_CTX:                     "OP_RESET_CTX",
	OP_SET_REG_INDEX:                 "OP_SET_REG_INDEX",
	OP_SET_READ_LEN:                  "OP_SET_READ_LEN",
	OP_SET_READ_LEN_REG_VALUE:        "OP_SET_READ_LEN_REG_VALUE",
	OP_SET_READ_LEN_POINTER_VALUE:    "OP_SET_READ_LEN_POINTER_VALUE",
	OP_SET_READ_COUNT:                "OP_SET_READ_COUNT",
	OP_ADD_OFFSET:                    "OP_ADD_OFFSET",
	OP_SUB_OFFSET:                    "OP_SUB_OFFSET",
	OP_MOVE_REG_VALUE:                "OP_MOVE_REG_VALUE",
	OP_MOVE_POINTER_VALUE:            "OP_MOVE_POINTER_VALUE",
	OP_MOVE_TMP_VALUE:                "OP_MOVE_TMP_VALUE",
	OP_SET_TMP_VALUE:                 "OP_SET_TMP_VALUE",
	OP_SET_BREAK_COUNT_REG_VALUE:     "OP_SET_BREAK_COUNT_REG_VALUE",
	OP_SET_BREAK_COUNT_POINTER_VALUE: "OP_SET_BREAK_COUNT_POINTER_VALUE",
	OP_SAVE_ADDR:                     "OP_SAVE_ADDR",
	OP_READ_REG:                      "OP_READ_REG",
	OP_SAVE_REG:                      "OP_SAVE_REG",
	OP_READ_POINTER:                  "OP_READ_POINTER",
	OP_SAVE_POINTER:                  "OP_SAVE_POINTER",
	OP_READ_STRUCT:                   "OP_READ_STRUCT",
	OP_SAVE_STRUCT:                   "OP_SAVE_STRUCT",
	OP_READ_STRING:                   "OP_READ_STRING",
	OP_SAVE_STRING:                   "OP_SAVE_STRING",
	OP_FOR_BREAK:                     "OP_FOR_BREAK",
	OP_RESET_BREAK:                   "OP_RESET_BREAK",
}

func GetOpName(op_code uint32) string {
	value, ok := OpMap[op_code]
	if ok {
		return value
	} else {
		panic(fmt.Sprintf("op_code:%d not exists", op_code))
	}
}

func ROPC(op_code uint32) OpConfig {
	opc := OpConfig{op_code, 0}
	op_key_helper.get_op_key(opc)
	return opc
}

// operation config
var OPC_SKIP = ROPC(OP_SKIP)
var OPC_RESET_CTX = ROPC(OP_RESET_CTX)
var OPC_SET_REG_INDEX = ROPC(OP_SET_REG_INDEX)
var OPC_SET_READ_LEN = ROPC(OP_SET_READ_LEN)
var OPC_SET_READ_LEN_REG_VALUE = ROPC(OP_SET_READ_LEN_REG_VALUE)
var OPC_SET_READ_LEN_POINTER_VALUE = ROPC(OP_SET_READ_LEN_POINTER_VALUE)
var OPC_SET_READ_COUNT = ROPC(OP_SET_READ_COUNT)
var OPC_ADD_OFFSET = ROPC(OP_ADD_OFFSET)
var OPC_SUB_OFFSET = ROPC(OP_SUB_OFFSET)
var OPC_MOVE_REG_VALUE = ROPC(OP_MOVE_REG_VALUE)
var OPC_MOVE_POINTER_VALUE = ROPC(OP_MOVE_POINTER_VALUE)
var OPC_MOVE_TMP_VALUE = ROPC(OP_MOVE_TMP_VALUE)
var OPC_SET_TMP_VALUE = ROPC(OP_SET_TMP_VALUE)
var OPC_SET_BREAK_COUNT_REG_VALUE = ROPC(OP_SET_BREAK_COUNT_REG_VALUE)
var OPC_SET_BREAK_COUNT_POINTER_VALUE = ROPC(OP_SET_BREAK_COUNT_POINTER_VALUE)
var OPC_SAVE_ADDR = ROPC(OP_SAVE_ADDR)
var OPC_READ_REG = ROPC(OP_READ_REG)
var OPC_SAVE_REG = ROPC(OP_SAVE_REG)
var OPC_READ_POINTER = ROPC(OP_READ_POINTER)
var OPC_SAVE_POINTER = ROPC(OP_SAVE_POINTER)
var OPC_READ_STRUCT = ROPC(OP_READ_STRUCT)
var OPC_SAVE_STRUCT = ROPC(OP_SAVE_STRUCT)
var OPC_READ_STRING = ROPC(OP_READ_STRING)
var OPC_SAVE_STRING = ROPC(OP_SAVE_STRING)
var OPC_FOR_BREAK = ROPC(OP_FOR_BREAK)
var OPC_RESET_BREAK = ROPC(OP_RESET_BREAK)

const (
	OP_LIST_COMMON_START uint32 = 0x400
)

type OpKeyHelper struct {
	op_list              map[uint32]OpConfig
	reg_index_op_key_map map[int]uint32
}

func (this *OpKeyHelper) show_all_op() {
	fmt.Printf("------------show_all_op(%d)------------\n", len(this.op_list))
	for k, v := range this.op_list {
		fmt.Printf("idx:%d, code:%d value:%4d %s\n", k, v.Code, v.Value, GetOpName(v.Code))
	}
	for check_index, check_v := range this.op_list {
		for index, v := range this.op_list {
			if index == check_index {
				continue
			}
			if v.Code == check_v.Code && v.Value == check_v.Value {
				fmt.Printf("[DUPLICATED] idx:%d, code:%d value:%4d %s\n", index, v.Code, v.Value, GetOpName(v.Code))
			}
		}
	}
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

func NewOpKeyHelper() *OpKeyHelper {
	helper := OpKeyHelper{}
	helper.op_list = make(map[uint32]OpConfig)
	helper.reg_index_op_key_map = make(map[int]uint32)
	return &helper
}

var op_key_helper = NewOpKeyHelper()

func GetOpList() map[uint32]OpConfig {
	return op_key_helper.GetOpList()
}

func RTO(alias_type, type_size uint32, ops ...OpConfig) OpArgType {
	new_opc := OPC_SET_READ_LEN.NewValue(uint64(type_size))
	new_op_key := op_key_helper.get_op_key(new_opc)
	oat := OpArgType{}
	oat.Alias_type = alias_type
	oat.Type_size = type_size
	oat.Ops = []uint32{new_op_key}
	for _, op_config := range ops {
		oat.Ops = append(oat.Ops, op_key_helper.get_op_key(op_config))
	}
	return oat
}

func X(arg_name string, arg_type *OpArgType) *ArgOpConfig {
	config := ArgOpConfig{}
	config.ArgName = arg_name
	config.AliasType = arg_type.Alias_type
	config.OpKeyList = arg_type.Ops
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
		op_key_config.AddOpK(op_key_helper.get_reg_index_op_key(reg_index))
		op_key_config.AddOpK(op_key_helper.get_op_key(OPC_READ_REG))
		op_key_config.AddOpK(op_key_helper.get_op_key(OPC_SAVE_REG))
		op_key_config.AddOpK(op_key_helper.get_op_key(OPC_MOVE_REG_VALUE))
		for _, op_key := range config.OpKeyList {
			op_key_config.AddOpK(op_key)
		}
	}
	// 关联到syscall
	aarch64_syscall_points.Add(nr, name, configs, NewOpKeyConfig(), op_key_config)
}

var OPA_INT32 = RTO(TYPE_INT32, uint32(unsafe.Sizeof(int32(0))))
var OPA_MSGHDR = RTO(TYPE_MSGHDR, uint32(unsafe.Sizeof(Msghdr{})), OPC_SAVE_STRUCT)
var OPA_IOV = RTO(TYPE_IOVEC, uint32(unsafe.Sizeof(syscall.Iovec{})), OPC_SAVE_STRUCT)
var OPA_BUFFER = RTO(TYPE_BUFFER, MAX_BUF_READ_SIZE, OPC_SAVE_STRUCT)

func init() {
	// 先准备好可选的 opc_set_reg_index 避免重复配置
	for reg_index := 0; reg_index < int(REG_ARM64_MAX); reg_index++ {
		new_opc := OPC_SET_REG_INDEX.NewValue(uint64(reg_index))
		op_key := op_key_helper.get_op_key(new_opc)
		op_key_helper.add_reg_index_op_config(reg_index, op_key)
	}
	// 对一些复杂结构体的读取配置进行补充

	// 读取 iov 注意 OPA_IOV 第一步会执行 OPC_SAVE_STRUCT
	// 将 op_ctx->read_addr 指向 iovec->iov_len
	OPA_IOV.AddOp(OPC_ADD_OFFSET, 8)
	// 读取 iovec->iov_len
	OPA_IOV.AddOpC(OP_READ_POINTER)
	// 设置 op_ctx->read_len 为默认的单次最大读取长度
	OPA_IOV.AddOp(OPC_SET_READ_LEN, uint64(MAX_BUF_READ_SIZE))
	// 修正 op_ctx->read_len
	OPA_IOV.AddOpC(OP_SET_READ_LEN_POINTER_VALUE)
	// 将 op_ctx->read_addr 重新指向 iovec 起始处
	OPA_IOV.AddOp(OPC_SUB_OFFSET, 8)
	// 读取 iovec->iov_base
	OPA_IOV.AddOpC(OP_READ_POINTER)
	// 转移 iovec->iov_base 到 op_ctx->read_addr
	OPA_IOV.AddOpC(OP_MOVE_POINTER_VALUE)
	// 读取 op_ctx->read_addr 处 op_ctx->read_len 长度的数据
	OPA_IOV.AddOpC(OP_SAVE_STRUCT)

	// 将 op_ctx->read_addr 保存到 op_ctx->tmp_value 也就是 msghdr 的地址
	OPA_MSGHDR.AddOpC(OP_SET_TMP_VALUE)
	// 将 op_ctx->read_addr 指向 msghdr->controllen
	OPA_MSGHDR.AddOp(OPC_ADD_OFFSET, 8+4+4+8+8+8)
	// 读取 msghdr->controllen
	OPA_MSGHDR.AddOpC(OP_READ_POINTER)
	// 设置 op_ctx->read_len 为默认的单次最大读取长度
	OPA_MSGHDR.AddOp(OPC_SET_READ_LEN, uint64(MAX_BUF_READ_SIZE))
	// 修正 op_ctx->read_len
	OPA_MSGHDR.AddOpC(OP_SET_READ_LEN_POINTER_VALUE)
	// 将 op_ctx->read_addr 指向 msghdr->control 起始处
	OPA_MSGHDR.AddOp(OPC_SUB_OFFSET, 8)
	// 读取 msghdr->control
	OPA_MSGHDR.AddOpC(OP_READ_POINTER)
	// 转移 msghdr->control 到 op_ctx->read_addr
	OPA_MSGHDR.AddOpC(OP_MOVE_POINTER_VALUE)
	// 读取 op_ctx->read_addr 处 op_ctx->read_len 长度的数据
	OPA_MSGHDR.AddOpC(OP_SAVE_STRUCT)
	// 恢复 op_ctx->tmp_value 也就是 op_ctx->read_addr 重新指向 msghdr
	OPA_MSGHDR.AddOpC(OP_MOVE_TMP_VALUE)

	// 将 op_ctx->read_addr 指向 msghdr->iovlen
	OPA_MSGHDR.AddOp(OPC_ADD_OFFSET, 8+4+4+8)
	// 读取 msghdr->iovlen
	OPA_MSGHDR.AddOpC(OP_READ_POINTER)
	// 将 iovlen 设置为循环次数上限
	OPA_MSGHDR.AddOpC(OP_SET_BREAK_COUNT_POINTER_VALUE)
	// 将读取地址指向 msghdr->iov
	OPA_MSGHDR.AddOp(OPC_SUB_OFFSET, 8)
	// 读取 msghdr->iov 指针
	OPA_MSGHDR.AddOpC(OP_READ_POINTER)
	// 将 op_ctx->read_addr 指向 msghdr->iov 指针
	OPA_MSGHDR.AddOpC(OP_MOVE_POINTER_VALUE)
	// 读取 msghdr->iov 最多读取 6 次 最少 msghdr->iovlen 次
	for i := 0; i < 6; i++ {
		OPA_MSGHDR.AddOp(OPC_FOR_BREAK, uint64(i))
		// 保存 iov 指针
		OPA_MSGHDR.AddOpC(OP_SAVE_ADDR)
		// 将读取地址放一份到临时变量中
		OPA_MSGHDR.AddOpC(OP_SET_TMP_VALUE)
		// 读取 iov 数据
		OPA_MSGHDR.AddOpA(OPA_IOV)
		// 恢复临时变量结果到 读取地址
		OPA_MSGHDR.AddOpC(OP_MOVE_TMP_VALUE)
		// 将 读取地址 偏移到下一个 iov 指针处
		OPA_MSGHDR.AddOp(OPC_ADD_OFFSET, 16)
	}
	OPA_MSGHDR.AddOpC(OP_RESET_BREAK)

	// 以指定寄存器为数据作为读取长度
	AT_BUFFER_X2 := AT_BUFFER.NewReadLenRegValue(REG_ARM64_X2)

	// 以指定寄存器为数据作为读取次数
	AT_IOVEC_X2 := AT_IOVEC.RepeatReadRegValue(REG_ARM64_X2)

	R(56, "openat", X("dirfd", AT_INT32), X("pathname", AT_STRING), X("flags", AT_INT32), X("mode", AT_INT16))
	R(66, "writev", X("fd", AT_INT32), X("iov", AT_IOVEC_X2), X("iovcnt", AT_INT32))
	R(206, "sendto", X("sockfd", AT_INT32), X("*buf", AT_BUFFER_X2), X("len", AT_INT32), X("flags", AT_INT32))

	// 测试时用
	// op_key_helper.show_all_op()

	// R(211, "sendmsg", X("sockfd", OPA_INT32), X("*msg", OPA_MSGHDR), X("flags", OPA_INT32))
}
