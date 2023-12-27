package argtype

import (
	"bytes"
	"fmt"
	. "stackplz/user/next/common"
)

type IArgType interface {
	Init(string, uint32, uint32, uint32)
	AddAlias(string)
	HasAliasName(string) bool
	DumpOpList()
	CleanOpList()
	SetSize(uint32)
	Clone() IArgType
	AddOp(*OpConfig)
	SetParseCB(ParseFN)
	// Setup()
	Parse(uint64, *bytes.Buffer, bool) string
	SetName(string)
	GetName() string
	SetTypeIndex(uint32)
	GetTypeIndex() uint32
	SetParentIndex(uint32)
	GetParentIndex() uint32
	GetSize() uint32
	AddOpList(p IArgType)
	GetOpList() []uint32
}

type ParseFN func(IArgType, uint64, *bytes.Buffer, bool) string

type ArgType struct {
	// 类型的名称
	Name string
	// 类型的预定义索引标识 一个类型可以附加其他的内容 比如结果解析时的输出形式
	// 又或者读取操作涉及到的大小不一样 所以这个是可以相同的
	// Alias    uint32
	BaseType uint32
	// 类型的唯一索引标识 用于取出实际类型
	TypeIndex   uint32
	ParentIndex uint32
	// 类型的大小 类似于 sizeof
	Size   uint32
	OpList []uint32
	// 可选的别名
	AliaNames []string
	ParseCB   ParseFN
}

func (this *ArgType) Init(name string, base_type, type_index, size uint32) {
	this.Name = name
	this.BaseType = base_type
	this.TypeIndex = type_index
	this.Size = size
}

func (this *ArgType) Clone() IArgType {
	at := ArgType{}
	at.Name = this.Name
	at.BaseType = this.BaseType
	at.TypeIndex = this.TypeIndex
	// ?
	at.ParentIndex = this.ParentIndex
	at.Size = this.Size
	at.OpList = append(at.OpList, this.OpList...)
	at.AliaNames = append(at.AliaNames, this.AliaNames...)
	at.ParseCB = this.ParseCB
	return &at
}

func (this *ArgType) AddAlias(alias_name string) {
	this.AliaNames = append(this.AliaNames, alias_name)
}

func (this *ArgType) HasAliasName(name string) bool {
	for _, alias_name := range this.AliaNames {
		if alias_name == name {
			return true
		}
	}
	return false
}

func (this *ArgType) DumpOpList() {
	fmt.Printf("DumpOpList for Name:%s Index:%d Count:%d\n", this.Name, this.TypeIndex, len(this.OpList))
	for index, op_index := range this.OpList {
		fmt.Printf("idx:%3d op_key:%3d %s\n", index, op_index, OPM.GetOpInfo(op_index))
	}
}

func (this *ArgType) AddOp(op *OpConfig) {
	this.OpList = append(this.OpList, OPM.AddOp(op).Index)
}

func (this *ArgType) SetParseCB(fn ParseFN) {
	this.ParseCB = fn
}

func (this *ArgType) AddOpList(p IArgType) {
	this.OpList = append(this.OpList, p.GetOpList()...)
}

func (this *ArgType) CleanOpList() {
	this.OpList = []uint32{}
}

func (this *ArgType) Parse(ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	panic(fmt.Sprintf("ArgType.Parse() not implemented yet, name=%s index=%d", this.Name, this.TypeIndex))
}

func (this *ArgType) SetSize(size uint32) {
	this.Size = size
}

func (this *ArgType) GetSize() uint32 {
	return this.Size
}

func (this *ArgType) SetName(name string) {
	this.Name = name
}

func (this *ArgType) GetName() string {
	return this.Name
}

func (this *ArgType) SetTypeIndex(index uint32) {
	this.TypeIndex = index
}

func (this *ArgType) GetTypeIndex() uint32 {
	return this.TypeIndex
}

func (this *ArgType) SetParentIndex(index uint32) {
	this.ParentIndex = index
}

func (this *ArgType) GetParentIndex() uint32 {
	return this.ParentIndex
}

func (this *ArgType) GetOpList() []uint32 {
	return this.OpList
}

var arg_types = make(map[uint32]IArgType)
var next_type_index = CONST_ARGTYPE_END

func NextTypeIndex() uint32 {
	next_type_index += 1
	return next_type_index
}

func GetArgType(type_index uint32) IArgType {
	p, ok := arg_types[type_index]
	if !ok {
		return LazyRegister(type_index)
	}
	return p
}

func GetArgTypeByName(name string) IArgType {
	for _, arg_type := range arg_types {
		if arg_type.GetName() == name {
			return arg_type
		}
		if arg_type.HasAliasName(name) {
			return arg_type
		}
	}
	panic(fmt.Sprintf("GetArgType failed, name=%s not exists", name))
}

func LazyRegister(type_index uint32) IArgType {
	// 所谓 lazy 也就是用到的时候再注册
	// 当然这是对复杂类型来说的 基础类型会提前准备好
	switch type_index {
	case STRING:
		return r_STRING()
	case STRING_ARRAY:
		return r_STRING_ARRAY()
	case BUFFER:
		return r_BUFFER()
	case MSGHDR:
		return r_MSGHDR()
	case IOVEC:
		return r_IOVEC()
	case IOVEC_X2:
		return r_IOVEC_X2()
	case SOCKADDR:
		return r_SOCKADDR()
	case BUFFER_X2:
		return r_BUFFER_X2()
	default:
		panic(fmt.Sprintf("LazyRegister for type_index:%d failed", type_index))
	}
}

func Register(p IArgType, name string, base, index, size uint32) {
	// 注册有预设的基础类型
	if p == nil {
		panic("Register ArgType is nil...")
	}
	p.Init(name, base, index, size)
	type_index := p.GetTypeIndex()
	if at, dup := arg_types[type_index]; dup {
		panic(fmt.Sprintf("duplicate register for ArgType name=%s index=%d", at.GetName(), at.GetTypeIndex()))
	}
	arg_types[type_index] = p
}

func RegisterPre(name string, type_index, parent_index uint32) IArgType {
	// 注册有预设的扩展类型
	if at, dup := arg_types[type_index]; dup {
		panic(fmt.Sprintf("duplicate register for ArgType name=%s index=%d", at.GetName(), at.GetTypeIndex()))
	}
	p := GetArgType(parent_index)
	new_p := p.Clone()
	new_p.SetName(name)
	new_p.SetTypeIndex(type_index)
	new_p.SetParentIndex(parent_index)
	arg_types[type_index] = new_p
	return new_p
}

func RegisterNew(name string, parent_index uint32) IArgType {
	// 动态注册新的类型 parent_index 即父类型的唯一索引
	return RegisterPre(name, NextTypeIndex(), parent_index)
}

func UpdateArgType(p IArgType) {
	arg_types[p.GetTypeIndex()] = p
}

func RegisterAlias(alias_name, name string) {
	GetArgTypeByName(name).AddAlias(alias_name)
}

func RegisterAliasType(type_index, alias_type_index uint32) IArgType {
	if at, dup := arg_types[type_index]; dup {
		panic(fmt.Sprintf("duplicate register for ArgType name=%s index=%d", at.GetName(), at.GetTypeIndex()))
	}
	p := GetArgType(alias_type_index)
	arg_types[type_index] = p
	return p
}
