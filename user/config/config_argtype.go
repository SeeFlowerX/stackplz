package config

import (
	"fmt"
	"syscall"
	"unsafe"
)

// 定义 arg_type 即定义读取一个 arg 所需要的操作集合

type OpArgType struct {
	Alias_type uint32
	Type_size  uint32
	Ops        []uint32
}

func (this *OpArgType) Clone() OpArgType {
	oat := OpArgType{}
	oat.Alias_type = this.Alias_type
	oat.Type_size = this.Type_size
	// 不能直接 copy 因为被赋值的一方长度为0
	oat.Ops = append(oat.Ops, this.Ops...)
	return oat
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
func (this *OpArgType) AddOpK(op_key uint32) {
	// add one op_key
	this.Ops = append(this.Ops, op_key)
}

func (this *OpArgType) NewReadLenRegValue(reg_index uint32) *OpArgType {
	if this.Alias_type != TYPE_BUFFER {
		panic(fmt.Sprintf("ArgType is %d, not TYPE_BUFFER", this.Alias_type))
	}
	at := this.Clone()
	at.Ops = []uint32{}
	for _, op_key := range this.Ops {
		at.AddOpK(op_key)
		op_config := op_key_helper.get_op_config(op_key)
		if op_config.Code == OP_SET_READ_LEN {
			// 以指定寄存器的值作为读取长度 需要插入以下操作
			at.AddOp(OPC_SET_REG_INDEX, uint64(reg_index))
			at.AddOpC(OP_READ_REG)
			at.AddOp(OPC_SET_READ_LEN_REG_VALUE, uint64(reg_index))
		}
	}
	return &at
}

func RAT(alias_type, type_size uint32) *OpArgType {
	// register OpArgType
	oat := OpArgType{}
	oat.Alias_type = alias_type
	oat.Type_size = type_size
	return &oat
}

// 基础类型
var AT_INT8 = RAT(TYPE_INT8, uint32(unsafe.Sizeof(int8(0))))
var AT_INT16 = RAT(TYPE_INT16, uint32(unsafe.Sizeof(int16(0))))
var AT_INT32 = RAT(TYPE_INT32, uint32(unsafe.Sizeof(int32(0))))
var AT_INT64 = RAT(TYPE_INT64, uint32(unsafe.Sizeof(int64(0))))

var AT_UINT8 = RAT(TYPE_UINT8, uint32(unsafe.Sizeof(uint8(0))))
var AT_UINT16 = RAT(TYPE_UINT16, uint32(unsafe.Sizeof(uint16(0))))
var AT_UINT32 = RAT(TYPE_UINT32, uint32(unsafe.Sizeof(uint32(0))))
var AT_UINT64 = RAT(TYPE_UINT64, uint32(unsafe.Sizeof(uint64(0))))

// 常用类型
var AT_BUFFER = RAT(TYPE_BUFFER, MAX_BUF_READ_SIZE)
var AT_STRING = RAT(TYPE_STRING, MAX_BUF_READ_SIZE)

// 复杂类型
var AT_MSGHDR = RAT(TYPE_MSGHDR, uint32(unsafe.Sizeof(Msghdr{})))
var AT_IOVEC = RAT(TYPE_IOVEC, uint32(unsafe.Sizeof(syscall.Iovec{})))

func init() {
	// 在这里完成各种类型的操作集合初始化

	// TYPE_BUFFER
	// 通常按照结构体的方式读取即可 即读取指定地址指定大小的数据即可
	// 然而数据大小有时候会通过其他参数指定
	// 所以在读取之前 比较预设的默认读取大小和指定大小 取小的那个
	// 这里先预设了读取长度 在实际使用时编排操作顺序
	AT_BUFFER.AddOp(OPC_SET_READ_LEN, uint64(MAX_BUF_READ_SIZE))
	AT_BUFFER.AddOpC(OP_SAVE_STRUCT)

	// TYPE_STRING
	AT_STRING.AddOpC(OP_SAVE_STRING)

	// Register(&SArgs{206, PAI("sendto", []PArg{A("sockfd", EXP_INT), A("buf", READ_BUFFER_T), A("len", INT), A("flags", EXP_INT), A("dest_addr", SOCKADDR), A("addrlen", EXP_INT)})})
}
