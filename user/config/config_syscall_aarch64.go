package config

import (
	"fmt"
	"strings"
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
	ArgValue  string
	OpKeyList []uint32
}

func (this *ArgOpConfig) IsPtr() bool {
	// 是否配置为指针类型
	return strings.HasPrefix(this.ArgName, "*")
}

type PointArgsConfig struct {
	PointName    string
	ArgsSysEnter OpKeyConfig
	ArgsSysExit  OpKeyConfig
}

// 基础类型配置
type OpArgType struct {
	// Type_alias_idx uint32
	// Type_base_idx  uint32
	Type_size uint32
	Ops       []uint32
}

// operation code enum
const (
	OP_SKIP uint32 = iota + 233
	OP_SET_REG_INDEX
	OP_SET_READ_LEN
	OP_SET_READ_COUNT
	OP_ADD_OFFSET
	OP_READ_REG
	OP_RESET_CTX
	OP_READ_POINTER
	OP_READ_STRUCT
	OP_READ_STRING
)

// operation config
var OPC_SKIP = OpConfig{OP_SKIP, 0}
var OPC_SET_REG_INDEX = OpConfig{OP_SET_REG_INDEX, 0}
var OPC_SET_READ_LEN = OpConfig{OP_SET_READ_LEN, 0}
var OPC_SET_READ_COUNT = OpConfig{OP_SET_READ_COUNT, 0}
var OPC_ADD_OFFSET = OpConfig{OP_ADD_OFFSET, 0}
var OPC_READ_REG = OpConfig{OP_READ_REG, 0}
var OPC_RESET_CTX = OpConfig{OP_RESET_CTX, 0}
var OPC_READ_POINTER = OpConfig{OP_READ_POINTER, 0}
var OPC_READ_STRUCT = OpConfig{OP_READ_STRUCT, 0}
var OPC_READ_STRING = OpConfig{OP_READ_STRING, 0}

const (
	OP_LIST_COMMON_START uint32 = 0x400
)

type OpKeyHelper struct {
	op_list              map[uint32]OpConfig
	reg_index_op_key_map map[int]uint32
}

func (this *OpKeyHelper) next_op_key() uint32 {
	return OP_LIST_COMMON_START + uint32(len(this.op_list))
}

func (this *OpKeyHelper) add_op_config(opc OpConfig) uint32 {
	// 如果已经有了那就直接用已有的 op_key
	for k, oc := range this.op_list {
		if oc.Code == opc.Code && oc.Value == opc.Value {
			return k
		}
	}
	op_key := this.next_op_key()
	this.op_list[op_key] = opc
	return op_key
}

func (this *OpKeyHelper) add_reg_index_op_config(reg_index int, opc OpConfig) {
	op_key := this.next_op_key()
	this.op_list[op_key] = opc
	this.reg_index_op_key_map[reg_index] = op_key
}

func (this *OpKeyHelper) get_reg_index_op_key(reg_index int) uint32 {
	return this.reg_index_op_key_map[reg_index]
}

func NewOpKeyHelper() *OpKeyHelper {
	helper := OpKeyHelper{}
	return &helper
}

var op_key_helper = NewOpKeyHelper()

func RTO(type_size uint32, ops ...uint32) OpArgType {
	opc := OPC_SET_READ_LEN.NewValue(uint64(type_size))
	op_key := op_key_helper.add_op_config(opc)
	oat := OpArgType{}
	oat.Type_size = type_size
	oat.Ops = []uint32{op_key}
	oat.Ops = append(oat.Ops, ops...)
	return oat
}

func X(arg_name string, arg_type OpArgType) *ArgOpConfig {
	config := ArgOpConfig{}
	config.ArgName = arg_name
	config.OpKeyList = arg_type.Ops
	return &config
}

var aarch64_syscall_points = make(map[string]OpKeyConfig)

func R(nr string, configs ...*ArgOpConfig) {
	// 不可重复
	if _, dup := aarch64_syscall_points[nr]; dup {
		panic(fmt.Sprintf("Register called twice for aarch64_syscall_points %s", nr))
	}
	// 合并多个参数的操作数
	var ops []uint32
	for reg_index, config := range configs {
		// 第一个操作是 OP_SET_REG_INDEX
		// 这里直接计算对应的 op_key
		ops = append(ops, op_key_helper.get_reg_index_op_key(reg_index))
		ops = append(ops, OP_READ_REG)
		// if config.IsPtr() {
		// 	ops = append(ops, OP_READ_REG)
		// }
		for _, op_key := range config.OpKeyList {
			ops = append(ops, op_key)
		}
	}
	// 检查操作数上限
	op_key_config := OpKeyConfig{}
	if len(ops) > len(op_key_config.OpKeyList) {
		panic(fmt.Sprintf("ops %d large than %d", len(ops), len(op_key_config.OpKeyList)))
	}
	// 复制操作数
	for i := 0; i < len(op_key_config.OpKeyList); i++ {
		if i < len(ops) {
			op_key_config.OpKeyList[i] = ops[i]
		} else {
			op_key_config.OpKeyList[i] = OP_SKIP
		}
	}
	// 关联到syscall
	aarch64_syscall_points[nr] = op_key_config
}

var OP_INT32 = RTO(uint32(unsafe.Sizeof(int32(0))))
var OP_MSGHDR = RTO(uint32(unsafe.Sizeof(Msghdr{})), OP_READ_STRUCT)

func init() {
	// 先准备好可选的 opc_set_reg_index 避免重复配置
	for reg_index := 0; reg_index < int(REG_ARM64_MAX); reg_index++ {
		opc := OPC_SET_REG_INDEX.NewValue(uint64(reg_index))
		op_key_helper.add_reg_index_op_config(reg_index, opc)
	}
	R("sendmsg", X("sockfd", OP_INT32), X("*msg", OP_MSGHDR), X("flags", OP_INT32))
}
