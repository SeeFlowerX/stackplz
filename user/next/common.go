package next

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
)

type IArgType interface {
	Init(string, uint32, uint32)
	AddAlias(string)
	HasAliasName(string) bool
	DumpOpList()
	CleanOpList()
	SetSize(uint32)
	Clone() IArgType
	AddOp(*OpConfig)
	SetParseCB(ParseFN)
	Setup()
	Parse(uint64, *bytes.Buffer, bool) string
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

type ParseFN func(IArgType, uint64, *bytes.Buffer, bool) string

type ArgType struct {
	Name        string
	Alias       uint32
	Size        uint32
	OpList      []uint32
	AliaNames   []string
	FlagsParser *FlagsParser
	ParseCB     ParseFN
}

func (this *ArgType) Init(name string, alias, size uint32) {
	this.Name = name
	this.Alias = alias
	this.Size = size
}

func (this *ArgType) Clone() IArgType {
	at := ArgType{}
	at.Name = this.Name
	at.Alias = this.Alias
	at.Size = this.Size
	at.OpList = append(at.OpList, this.OpList...)
	at.AliaNames = append(at.AliaNames, this.AliaNames...)
	at.FlagsParser = this.FlagsParser
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
	fmt.Printf("DumpOpList for Name:%s Alias:%d Count:%d\n", this.Name, this.Alias, len(this.OpList))
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

func (this *ArgType) Setup() {
	panic(fmt.Sprintf("ArgType.Setup() not implemented yet, name=%s index=%d", this.Name, this.Alias))
}

func (this *ArgType) Parse(ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	panic(fmt.Sprintf("ArgType.Parse() not implemented yet, name=%s index=%d", this.Name, this.Alias))
}

func (this *ArgType) ParseArgStruct(buf *bytes.Buffer, arg ArgFormatter) string {
	if err := binary.Read(buf, binary.LittleEndian, arg); err != nil {
		time.Sleep(3 * 100 * time.Millisecond)
		panic(err)
	}
	return arg.Format()
}

func (this *ArgType) SetSize(size uint32) {
	this.Size = size
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
	Name      string
	RegIndex  uint32
	Type      IArgType
	OpList    []uint32
	PointType uint32
}

func (this *PointArg) SetRegIndex(reg_index uint32) {
	this.RegIndex = reg_index
}

func (this *PointArg) BuildOpList(read_full bool) {
	this.OpList = append(this.OpList, Add_READ_SAVE_REG(uint64(this.RegIndex)).Index)
	this.OpList = append(this.OpList, OPC_MOVE_REG_VALUE.Index)
	if read_full {
		for _, op_key := range this.Type.GetOpList() {
			this.OpList = append(this.OpList, op_key)
		}
	}
}

func (this *PointArg) GetOpList() []uint32 {
	return this.OpList
}

func (this *PointArg) Clone() *PointArg {
	p := PointArg{}
	p.Name = this.Name
	p.RegIndex = this.RegIndex
	p.Type = this.Type
	p.OpList = append(p.OpList, this.OpList...)
	p.PointType = this.PointType
	return &p
}

func NewPointArg(arg_name string, arg_type IArgType, point_type uint32) *PointArg {
	point_arg := PointArg{}
	point_arg.Name = arg_name
	point_arg.RegIndex = REG_ARM64_MAX
	point_arg.Type = arg_type
	point_arg.PointType = point_type
	return &point_arg
}

var arg_types = make(map[uint32]IArgType)

func GetArgType(name string) IArgType {
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

func RegisterAlias(alias_name, name string) {
	GetArgType(name).AddAlias(alias_name)
}
