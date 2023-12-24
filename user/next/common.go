package next

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
)

type IArgType interface {
	Init(string, uint32, uint32)
	DumpOpList()
	Setup()
	Parse(uint64, *bytes.Buffer) string
	GetName() string
	GetSize() uint32
	GetAlias() uint32
	GetOpList() []uint32
}

type BaseOpConfig struct {
	Code     uint32
	PreCode  uint32
	PostCode uint32
	Value    uint64
}

type OpConfig struct {
	Name  string
	Index uint32
	BaseOpConfig
}

type ArgType struct {
	Name   string
	Alias  uint32
	Size   uint32
	OpList []uint32
}

func (this *ArgType) Init(name string, alias, size uint32) {
	this.Name = name
	this.Alias = alias
	this.Size = size
}

func (this *ArgType) DumpOpList() {
	fmt.Printf("DumpOpList for Name:%s Alias:%d Count:%d\n", this.Name, this.Alias, len(this.OpList))
	for index, op_index := range this.OpList {
		fmt.Printf("idx:%3d op_key:%3d %s\n", index, op_index, OPM.GetOpInfo(op_index))
	}
}

func (this *ArgType) AddOp(op *OpConfig) {
	this.OpList = append(this.OpList, OPM.AddOp(op).Index)
}

func (this *ArgType) Setup() {
	panic(fmt.Sprintf("ArgType.Setup() not implemented yet, name=%s index=%d", this.Name, this.Alias))
}

func (this *ArgType) SetupSaveStruct() {
	op := OPC_SET_READ_LEN.NewValue(uint64(this.Size))
	this.AddOp(op.NewPostCode(OP_SAVE_STRUCT))
}

func (this *ArgType) Parse() {
	panic(fmt.Sprintf("ArgType.Parse() not implemented yet, name=%s index=%d", this.Name, this.Alias))
}

func (this *ArgType) ParseArgStruct(buf *bytes.Buffer, arg ArgFormatter) string {
	if err := binary.Read(buf, binary.LittleEndian, arg); err != nil {
		time.Sleep(3 * 100 * time.Millisecond)
		panic(err)
	}
	return arg.Format()
}

func (this *ArgType) GetName() string {
	return this.Name
}

func (this *ArgType) GetSize() uint32 {
	return this.Size
}

func (this *ArgType) GetAlias() uint32 {
	return this.Alias
}

func (this *ArgType) GetOpList() []uint32 {
	return this.OpList
}

type PointArg struct {
	Name     string
	RegIndex uint32
	Type     IArgType
	OpList   []uint32
}

func (this *PointArg) SetRegIndex(reg_index uint32) {
	this.RegIndex = reg_index
}

func (this *PointArg) BuildOpList() {
	this.OpList = append(this.OpList, Add_READ_SAVE_REG(uint64(this.RegIndex)).Index)
	this.OpList = append(this.OpList, OPC_MOVE_REG_VALUE.Index)
	for _, op_key := range this.Type.GetOpList() {
		this.OpList = append(this.OpList, op_key)
	}
}

func (this *PointArg) GetOpList() []uint32 {
	return this.OpList
}

func NewPointArg(arg_name string, arg_type IArgType) *PointArg {
	point_arg := PointArg{}
	point_arg.Name = arg_name
	point_arg.RegIndex = REG_ARM64_MAX
	point_arg.Type = arg_type
	return &point_arg
}

var arg_types = make(map[uint32]IArgType)

func GetArgType(alias uint32) IArgType {
	v, ok := arg_types[alias]
	if ok {
		return v
	}
	panic(fmt.Sprintf("GetArgType failed, index=%d not exists", alias))
}

func Register(p IArgType, name string, alias, size uint32) {
	if p == nil {
		panic("Register ArgType is nil...")
	}
	p.Init(name, alias, size)
	type_index := p.GetAlias()
	if at, dup := arg_types[type_index]; dup {
		panic(fmt.Sprintf("Register called twice for ArgType name=%s index=%d", at.GetName(), at.GetAlias()))
	}
	p.Setup()
	arg_types[type_index] = p
}
