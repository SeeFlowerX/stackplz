package config

import (
	"fmt"
	"log"
	. "stackplz/user/common"
)

type IConfig interface {
	SetDebug(bool)
	Info() string
}

type BaseConfig struct {
	Debug  bool
	logger *log.Logger
}

func (this *BaseConfig) SetLogger(logger *log.Logger) {
	this.logger = logger
}

func (this *BaseConfig) GetLogger() *log.Logger {
	return this.logger
}

func (this *BaseConfig) SetDebug(debug bool) {
	this.Debug = debug
}

func (this *BaseConfig) Info() string {
	panic("BaseConfig.Info() not implemented yet")
}

var RegsMagicMap map[string]uint32 = map[string]uint32{
	"x0":  REG_ARM64_X0,
	"x1":  REG_ARM64_X1,
	"x2":  REG_ARM64_X2,
	"x3":  REG_ARM64_X3,
	"x4":  REG_ARM64_X4,
	"x5":  REG_ARM64_X5,
	"x6":  REG_ARM64_X6,
	"x7":  REG_ARM64_X7,
	"x8":  REG_ARM64_X8,
	"x9":  REG_ARM64_X9,
	"x10": REG_ARM64_X10,
	"x11": REG_ARM64_X11,
	"x12": REG_ARM64_X12,
	"x13": REG_ARM64_X13,
	"x14": REG_ARM64_X14,
	"x15": REG_ARM64_X15,
	"x16": REG_ARM64_X16,
	"x17": REG_ARM64_X17,
	"x18": REG_ARM64_X18,
	"x19": REG_ARM64_X19,
	"x20": REG_ARM64_X20,
	"x21": REG_ARM64_X21,
	"x22": REG_ARM64_X22,
	"x23": REG_ARM64_X23,
	"x24": REG_ARM64_X24,
	"x25": REG_ARM64_X25,
	"x26": REG_ARM64_X26,
	"x27": REG_ARM64_X27,
	"x28": REG_ARM64_X28,
	"x29": REG_ARM64_X29,
	"lr":  REG_ARM64_LR,
	"sp":  REG_ARM64_SP,
	"pc":  REG_ARM64_PC,
}

func GetRegIndex(reg string) uint32 {
	value, ok := RegsMagicMap[reg]
	if !ok {
		panic(fmt.Sprintf("ParseAsReg failed =>%s<=", reg))
	}
	return value
}

type PointOpKeyConfig struct {
	OpCount   uint32
	OpKeyList [MAX_OP_COUNT]uint32
}

func (this *PointOpKeyConfig) AddPointArg(point_arg *PointArg) {
	for _, op_key := range point_arg.GetOpList() {
		this.OpKeyList[this.OpCount] = op_key
		this.OpCount++
		if this.OpCount == MAX_OP_COUNT {
			panic("PointOpKeyConfig->AddPointArg failed, need increase MAX_OP_COUNT")
		}
	}
}
