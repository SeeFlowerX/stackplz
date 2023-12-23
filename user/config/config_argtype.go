package config

import (
	"fmt"
	"syscall"
	"unsafe"
)

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
	OP_FOR_BREAK
	OP_SET_BREAK_COUNT_REG_VALUE
	OP_SET_BREAK_COUNT_POINTER_VALUE
	OP_SAVE_ADDR
	OP_READ_REG
	OP_SAVE_REG
	OP_READ_POINTER
	OP_SAVE_POINTER
	OP_SAVE_STRUCT
	OP_SAVE_STRING
)

func NewOpManager() *OpManager {
	opm := OpManager{}
	return &opm
}

func GetOpList() map[uint32]OpConfig_C {
	return OPM.GetOpList()
}

func ROP(name string, code uint32) *OpConfig {
	// 注册基础的操作 直接添加
	op := &OpConfig{}
	op.Name = name
	op.Code = code
	op.PreCode = OP_SKIP
	op.PostCode = OP_SKIP
	return OPM.AddOp(op)
}

func Add_READ_SAVE_REG(value uint64) *OpConfig {
	// 三合一
	op := &OpConfig{}
	op.Name = fmt.Sprintf("%s_%d", "READ_SAVE_REG", value)
	op.Code = OP_READ_REG
	op.PreCode = OP_SET_REG_INDEX
	op.PostCode = OP_SAVE_REG
	op.Value = value
	return OPM.AddOp(op)
}

type OpManager struct {
	OpList []*OpConfig
}

func (this *OpManager) Count() uint32 {
	return uint32(len(this.OpList))
}

func (this *OpManager) AddOp(op *OpConfig) *OpConfig {
	for _, v := range this.OpList {
		if v.SameAs(op) {
			return v
		}
	}
	op.Index = this.Count()
	this.OpList = append(this.OpList, op)
	return op
}

func (this *OpManager) GetOpList() map[uint32]OpConfig_C {
	var c_op_list = make(map[uint32]OpConfig_C)
	for _, v := range this.OpList {
		c_op_list[v.Index] = v.ToEbpfValue()
		// fmt.Println("..", i, v.Index, c_op_list[v.Index], v.Name)
	}
	return c_op_list
}

type OpConfig_C struct {
	Code     uint32
	PreCode  uint32
	PostCode uint32
	Value    uint64
}

type OpConfig struct {
	Name  string
	Index uint32
	OpConfig_C
}

func (this *OpConfig) ToEbpfValue() OpConfig_C {
	v := OpConfig_C{}
	v.Code = this.Code
	v.PreCode = this.PreCode
	v.PostCode = this.PostCode
	v.Value = this.Value
	return v
}

func (this *OpConfig) SameAs(op *OpConfig) bool {
	if this.Name != op.Name {
		return false
	}
	if this.Code != op.Code {
		return false
	}
	// if this.Index != op.Index {
	// 	return false
	// }
	if this.PreCode != op.PreCode {
		return false
	}
	if this.PostCode != op.PostCode {
		return false
	}
	if this.Value != op.Value {
		return false
	}
	return true
}

func (this *OpConfig) Clone() *OpConfig {
	op := &OpConfig{}
	op.Name = this.Name
	op.Index = this.Index
	op.Code = this.Code
	op.PreCode = this.PreCode
	op.PostCode = this.PostCode
	op.Value = this.Value
	return op
}

func (this *OpConfig) NewValue(value uint64) *OpConfig {
	op := this.Clone()
	op.Value = value
	return OPM.AddOp(op)
}

func (this *OpConfig) NewPreCode(pre_code uint32) *OpConfig {
	op := this.Clone()
	op.PreCode = pre_code
	return OPM.AddOp(op)
}

func (this *OpConfig) NewPostCode(post_code uint32) *OpConfig {
	op := this.Clone()
	op.PostCode = post_code
	return OPM.AddOp(op)
}

// 定义 arg_type 即定义读取一个 arg 所需要的操作集合

type OpArgType struct {
	Alias_type uint32
	Type_size  uint32
	OpList     []*OpConfig
}

func (this *OpArgType) Clone() OpArgType {
	oat := OpArgType{}
	oat.Alias_type = this.Alias_type
	oat.Type_size = this.Type_size
	// 不能直接 copy 因为被赋值的一方长度为0
	oat.OpList = append(oat.OpList, this.OpList...)
	return oat
}

func (this *OpArgType) AddOp(op *OpConfig) {
	this.OpList = append(this.OpList, OPM.AddOp(op))
}

func BuildBufferRegIndex(reg_index uint32) *OpArgType {
	at := AT_BUFFER.Clone()
	at.AddOp(OPC_SET_READ_LEN.NewValue(uint64(at.Type_size)))
	at.AddOp(BuildReadRegLen(uint64(reg_index)))
	at.AddOp(OPC_SAVE_STRUCT)
	return &at
}

func BuildIovecRegIndex(reg_index uint32) *OpArgType {
	at := AT_IOVEC.Clone()
	op := BuildReadRegBreakCount(uint64(reg_index))
	op = OPM.AddOp(op)
	var for_op []*OpConfig = []*OpConfig{op, OPC_SAVE_REG, OPC_FOR_BREAK, OPC_SET_TMP_VALUE}
	at.OpList = append(for_op, at.OpList...)
	at.AddOp(OPC_MOVE_TMP_VALUE)
	at.AddOp(OPC_ADD_OFFSET.NewValue(16))
	at.AddOp(OPC_FOR_BREAK)
	return &at
}

func RAT(alias_type, type_size uint32) *OpArgType {
	// register common OpArgType
	oat := OpArgType{}
	oat.Alias_type = alias_type
	oat.Type_size = type_size
	return &oat
}

func RSAT(alias_type, type_size uint32) *OpArgType {
	// register struct OpArgType
	oat := &OpArgType{}
	oat.Alias_type = alias_type
	oat.Type_size = type_size
	op := OPC_SET_READ_LEN.NewValue(uint64(type_size))
	oat.AddOp(op.NewPostCode(OP_SAVE_STRUCT))
	return oat
}

var OPM = NewOpManager()

var OPC_SKIP = ROP("SKIP", OP_SKIP)
var OPC_RESET_CTX = ROP("RESET_CTX", OP_RESET_CTX)
var OPC_SET_REG_INDEX = ROP("SET_REG_INDEX", OP_SET_REG_INDEX)
var OPC_SET_READ_LEN = ROP("SET_READ_LEN", OP_SET_READ_LEN)
var OPC_SET_READ_LEN_REG_VALUE = ROP("SET_READ_LEN_REG_VALUE", OP_SET_READ_LEN_REG_VALUE)
var OPC_SET_READ_LEN_POINTER_VALUE = ROP("SET_READ_LEN_POINTER_VALUE", OP_SET_READ_LEN_POINTER_VALUE)
var OPC_SET_READ_COUNT = ROP("SET_READ_COUNT", OP_SET_READ_COUNT)
var OPC_ADD_OFFSET = ROP("ADD_OFFSET", OP_ADD_OFFSET)
var OPC_SUB_OFFSET = ROP("SUB_OFFSET", OP_SUB_OFFSET)
var OPC_MOVE_REG_VALUE = ROP("MOVE_REG_VALUE", OP_MOVE_REG_VALUE)
var OPC_MOVE_POINTER_VALUE = ROP("MOVE_POINTER_VALUE", OP_MOVE_POINTER_VALUE)
var OPC_MOVE_TMP_VALUE = ROP("MOVE_TMP_VALUE", OP_MOVE_TMP_VALUE)
var OPC_SET_TMP_VALUE = ROP("SET_TMP_VALUE", OP_SET_TMP_VALUE)
var OPC_FOR_BREAK = ROP("FOR_BREAK", OP_FOR_BREAK)
var OPC_SET_BREAK_COUNT_REG_VALUE = ROP("SET_BREAK_COUNT_REG_VALUE", OP_SET_BREAK_COUNT_REG_VALUE)
var OPC_SET_BREAK_COUNT_POINTER_VALUE = ROP("SET_BREAK_COUNT_POINTER_VALUE", OP_SET_BREAK_COUNT_POINTER_VALUE)
var OPC_SAVE_ADDR = ROP("SAVE_ADDR", OP_SAVE_ADDR)
var OPC_READ_REG = ROP("READ_REG", OP_READ_REG)
var OPC_SAVE_REG = ROP("SAVE_REG", OP_SAVE_REG)
var OPC_READ_POINTER = ROP("READ_POINTER", OP_READ_POINTER)
var OPC_SAVE_POINTER = ROP("SAVE_POINTER", OP_SAVE_POINTER)
var OPC_SAVE_STRUCT = ROP("SAVE_STRUCT", OP_SAVE_STRUCT)
var OPC_SAVE_STRING = ROP("SAVE_STRING", OP_SAVE_STRING)

// 基础类型
var AT_INT8 = RAT(TYPE_INT8, uint32(unsafe.Sizeof(int8(0))))
var AT_INT16 = RAT(TYPE_INT16, uint32(unsafe.Sizeof(int16(0))))
var AT_INT32 = RAT(TYPE_INT32, uint32(unsafe.Sizeof(int32(0))))
var AT_INT64 = RAT(TYPE_INT64, uint32(unsafe.Sizeof(int64(0))))

var AT_INT = AT_INT32

var AT_UINT8 = RAT(TYPE_UINT8, uint32(unsafe.Sizeof(uint8(0))))
var AT_UINT16 = RAT(TYPE_UINT16, uint32(unsafe.Sizeof(uint16(0))))
var AT_UINT32 = RAT(TYPE_UINT32, uint32(unsafe.Sizeof(uint32(0))))
var AT_UINT64 = RAT(TYPE_UINT64, uint32(unsafe.Sizeof(uint64(0))))

// 常用类型
var AT_BUFFER = RAT(TYPE_BUFFER, MAX_BUF_READ_SIZE)
var AT_STRING = RAT(TYPE_STRING, MAX_BUF_READ_SIZE)

// 复杂类型
var AT_STAT = RSAT(TYPE_STAT, uint32(unsafe.Sizeof(syscall.Stat_t{})))
var AT_SOCKADDR = RSAT(TYPE_SOCKADDR, uint32(unsafe.Sizeof(syscall.RawSockaddrUnix{})))
var AT_IOVEC = RSAT(TYPE_IOVEC, uint32(unsafe.Sizeof(syscall.Iovec{})))
var AT_MSGHDR = RSAT(TYPE_MSGHDR, uint32(unsafe.Sizeof(Msghdr{})))

func BuildReadRegBreakCount(reg_index uint64) *OpConfig {
	op := OpConfig{}
	op.Name = fmt.Sprintf("%s_%d", "READ_REG_AS_BREAK_COUNT", reg_index)
	op.Code = OP_READ_REG
	op.PreCode = OP_SET_REG_INDEX
	op.PostCode = OP_SET_BREAK_COUNT_REG_VALUE
	op.Value = reg_index
	return &op
}

func BuildReadPtrBreakCount(offset uint64) *OpConfig {
	op := OpConfig{}
	op.Name = fmt.Sprintf("%s_%d", "READ_PTR_AS_BREAK_COUNT", offset)
	op.Code = OP_READ_POINTER
	op.PreCode = OP_ADD_OFFSET
	op.PostCode = OP_SET_BREAK_COUNT_POINTER_VALUE
	op.Value = offset
	return &op
}

func BuildReadRegLen(reg_index uint64) *OpConfig {
	op := OpConfig{}
	op.Name = fmt.Sprintf("%s_%d", "READ_REG_AS_READ_LEN", reg_index)
	op.Code = OP_READ_REG
	op.PreCode = OP_SET_REG_INDEX
	op.PostCode = OP_SET_READ_LEN_REG_VALUE
	op.Value = reg_index
	return &op
}

func BuildReadPtrLen(offset uint64) *OpConfig {
	op := OpConfig{}
	op.Name = fmt.Sprintf("%s_%d", "READ_PTR_AS_READ_LEN", offset)
	op.Code = OP_READ_POINTER
	op.PreCode = OP_ADD_OFFSET
	op.PostCode = OP_SET_READ_LEN_POINTER_VALUE
	op.Value = offset
	return &op
}

func BuildReadPtrAddr(offset uint64) *OpConfig {
	op := OpConfig{}
	op.Name = fmt.Sprintf("%s_%d", "READ_PTR_AS_ADDR", offset)
	op.Code = OP_READ_POINTER
	op.PreCode = OP_ADD_OFFSET
	op.PostCode = OP_MOVE_POINTER_VALUE
	op.Value = offset
	return &op
}

func BuildMsghdr() {
	t := Msghdr{}
	AT_MSGHDR.AddOp(OPC_SET_TMP_VALUE)
	AT_MSGHDR.AddOp(OPC_SET_READ_LEN.NewValue(uint64(MAX_BUF_READ_SIZE)))
	AT_MSGHDR.AddOp(BuildReadPtrLen(uint64(unsafe.Offsetof(t.Controllen))))
	AT_MSGHDR.AddOp(BuildReadPtrAddr(uint64(unsafe.Offsetof(t.Control))))
	AT_MSGHDR.AddOp(OPC_SAVE_STRUCT)
	AT_MSGHDR.AddOp(OPC_MOVE_TMP_VALUE)
	AT_MSGHDR.AddOp(BuildReadPtrBreakCount(uint64(unsafe.Offsetof(t.Iovlen))))
	// 由于结构体直接可以取到长度 这里就不再保存一次了
	// AT_MSGHDR.AddOp(OPC_SAVE_POINTER)
	AT_MSGHDR.AddOp(BuildReadPtrAddr(uint64(unsafe.Offsetof(t.Iov))))
	AT_MSGHDR.AddOp(OPC_SET_TMP_VALUE)
	AT_MSGHDR.AddOp(OPC_FOR_BREAK)
	AT_MSGHDR.OpList = append(AT_MSGHDR.OpList, AT_IOVEC.OpList...)
	AT_MSGHDR.AddOp(OPC_MOVE_TMP_VALUE)
	AT_MSGHDR.AddOp(OPC_ADD_OFFSET.NewValue(uint64(AT_IOVEC.Type_size)))
	AT_MSGHDR.AddOp(OPC_FOR_BREAK)

}

func init() {
	// 在这里完成各种类型的操作集合初始化

	// TYPE_STRING
	AT_STRING.AddOp(OPC_SAVE_STRING)

	// TYPE_IOVEC
	AT_IOVEC.AddOp(OPC_SET_READ_LEN.NewValue(uint64(MAX_BUF_READ_SIZE)))
	AT_IOVEC.AddOp(BuildReadPtrLen(8))
	AT_IOVEC.AddOp(OPC_READ_POINTER)
	AT_IOVEC.AddOp(OPC_MOVE_POINTER_VALUE)
	AT_IOVEC.AddOp(OPC_SAVE_STRUCT)

	// TYPE_MSGHDR
	BuildMsghdr()

	// Register(&SArgs{206, PAI("sendto", []PArg{A("sockfd", EXP_INT), A("buf", READ_BUFFER_T), A("len", INT), A("flags", EXP_INT), A("dest_addr", SOCKADDR), A("addrlen", EXP_INT)})})
}
