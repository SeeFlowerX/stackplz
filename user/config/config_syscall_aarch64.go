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
	panic(fmt.Sprintf("GetPointByNR failed for nr %s", nr))
}

func GetSyscallPointByName(name string) *PointArgsConfig {
	return aarch64_syscall_points.GetPointByName(name)
}

func GetSyscallPointByNR(nr uint32) *PointArgsConfig {
	return aarch64_syscall_points.GetPointByNR(nr)
}

// 基础类型配置
type OpArgType struct {
	Alias_type uint32
	Type_size  uint32
	Ops        []uint32
}

func (this *OpArgType) AddOp(opc OpConfig, value uint64) {
	new_op_key := op_key_helper.get_op_key(opc.NewValue(value))
	this.Ops = append(this.Ops, new_op_key)
}

func (this *OpArgType) AddOpC(op_code uint32) {
	// add one op with default value
	default_op_key := op_key_helper.get_default_op_key(op_code)
	this.Ops = append(this.Ops, default_op_key)
}

func (this *OpArgType) AddOpA(arg_type OpArgType) {
	// add one arg op_keys
	for _, arg_op_key := range arg_type.Ops {
		this.Ops = append(this.Ops, arg_op_key)
	}
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

func NewOpKeyHelper() *OpKeyHelper {
	helper := OpKeyHelper{}
	helper.op_list = make(map[uint32]OpConfig)
	helper.reg_index_op_key_map = make(map[int]uint32)
	return &helper
}

var op_key_helper = NewOpKeyHelper()

func GetOpList() *map[uint32]OpConfig {
	return &op_key_helper.op_list
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

func X(arg_name string, arg_type OpArgType) *ArgOpConfig {
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
	// 合并多个参数的操作数
	var ops []uint32
	for reg_index, config := range configs {
		// 第一个操作是 OP_SET_REG_INDEX
		// 这里直接计算对应的 op_key
		ops = append(ops, op_key_helper.get_reg_index_op_key(reg_index))
		ops = append(ops, op_key_helper.get_op_key(OPC_READ_REG))
		ops = append(ops, op_key_helper.get_op_key(OPC_SAVE_REG))
		ops = append(ops, op_key_helper.get_op_key(OPC_MOVE_REG_VALUE))
		for _, op_key := range config.OpKeyList {
			ops = append(ops, op_key)
		}
	}
	fmt.Println("len(ops)", len(ops))
	// 检查操作数上限
	op_key_config := OpKeyConfig{}
	if len(ops) > len(op_key_config.OpKeyList) {
		panic(fmt.Sprintf("ops count %d large than %d", len(ops), len(op_key_config.OpKeyList)))
	}
	// 复制操作数
	for i := 0; i < len(op_key_config.OpKeyList); i++ {
		if i < len(ops) {
			op_key_config.OpKeyList[i] = ops[i]
			op_key_config.OpCount++
		} else {
			// 这里不设置也可以 因为有 op_count 决定循环次数
			op_key_config.OpKeyList[i] = op_key_helper.get_op_key(OPC_SKIP)
		}
	}
	// 关联到syscall
	aarch64_syscall_points.Add(nr, name, configs, OpKeyConfig{}, op_key_config)
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

	// 读取 iov 数据
	OPA_IOV.AddOp(OPC_ADD_OFFSET, 8)
	OPA_IOV.AddOpC(OP_READ_POINTER)
	OPA_IOV.AddOp(OPC_SET_READ_LEN, uint64(MAX_BUF_READ_SIZE))
	OPA_IOV.AddOpC(OP_SET_READ_LEN_POINTER_VALUE)
	OPA_IOV.AddOp(OPC_SUB_OFFSET, 8)
	OPA_IOV.AddOpC(OP_READ_POINTER)
	OPA_IOV.AddOpC(OP_MOVE_POINTER_VALUE)
	OPA_IOV.AddOpC(OP_SAVE_STRUCT)

	// 将读取地址指向 iovlen
	OPA_MSGHDR.AddOp(OPC_ADD_OFFSET, 8+4+4+8)
	// 读取 iovlen
	OPA_MSGHDR.AddOpC(OP_READ_POINTER)
	// 将 iovlen 设置为循环次数上限
	OPA_MSGHDR.AddOpC(OP_SET_BREAK_COUNT_POINTER_VALUE)
	// 将读取地址指向 iov
	OPA_MSGHDR.AddOp(OPC_SUB_OFFSET, 8)
	// 取出 iov 指针
	OPA_MSGHDR.AddOpC(OP_READ_POINTER)
	// 保存 iov 指针
	OPA_MSGHDR.AddOpC(OP_SAVE_POINTER)
	// 将读取地址指向取出的 iov 指针
	OPA_MSGHDR.AddOpC(OP_MOVE_POINTER_VALUE)
	// 将读取地址放一份到临时变量中
	OPA_MSGHDR.AddOpC(OP_SET_TMP_VALUE)
	// 读取 iov 结构体 设置最多读取6次
	for i := 0; i < 6; i++ {
		OPA_MSGHDR.AddOp(OPC_FOR_BREAK, uint64(i))
		OPA_MSGHDR.AddOpC(OP_READ_POINTER)
		OPA_MSGHDR.AddOpC(OP_MOVE_POINTER_VALUE)
		OPA_MSGHDR.AddOpA(OPA_IOV)
		// 恢复临时变量结果到 读取地址
		OPA_MSGHDR.AddOpC(OP_MOVE_TMP_VALUE)
		// 将 读取地址 偏移一个指针大小
		OPA_MSGHDR.AddOp(OPC_ADD_OFFSET, 8)
		// 更新临时变量
		OPA_MSGHDR.AddOpC(OP_SET_TMP_VALUE)
	}
	OPA_MSGHDR.AddOpC(OP_RESET_BREAK)

	R(211, "sendmsg", X("sockfd", OPA_INT32), X("*msg", OPA_MSGHDR), X("flags", OPA_INT32))
}
