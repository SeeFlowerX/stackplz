package config

import (
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

type SyscallPointOpKeyConfig struct {
	Signal    uint32
	OpCount   uint32
	OpKeyList [SYSCALL_MAX_OP_COUNT]uint32
}

type UprobePointOpKeyConfig struct {
	Signal    uint32
	OpCount   uint32
	OpKeyList [STACK_MAX_OP_COUNT]uint32
}

func (this *SyscallPointOpKeyConfig) AddPointArg(point_arg *PointArg) {
	for _, op_key := range point_arg.GetOpList() {
		this.OpKeyList[this.OpCount] = op_key
		this.OpCount++
		if this.OpCount == uint32(len(this.OpKeyList)) {
			panic("SyscallPointOpKeyConfig->AddPointArg failed, need increase max op count")
		}
	}
}
func (this *UprobePointOpKeyConfig) AddPointArg(point_arg *PointArg) {
	for _, op_key := range point_arg.GetOpList() {
		this.OpKeyList[this.OpCount] = op_key
		this.OpCount++
		if this.OpCount == uint32(len(this.OpKeyList)) {
			panic("SyscallPointOpKeyConfig->AddPointArg failed, need increase max op count")
		}
	}
}
