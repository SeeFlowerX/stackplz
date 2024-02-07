package config

import (
	"fmt"
	"stackplz/user/argtype"
	"strings"
)

type UprobeArgs struct {
	Index        uint32
	EnterKey     uint32
	LibPath      string
	RealFilePath string
	Name         string
	Symbol       string
	Offset       uint64
	NonElfOffset uint64
	ArgsStr      string
	PointArgs    []*PointArg
	BindSyscall  bool
	ExitRead     bool
	ExitOffset   uint64
	KillSignal   uint32
}

func (this *UprobeArgs) GetExitPoint(index int) *UprobeArgs {
	// 这样标记为需要保存这个位置的寄存器
	this.EnterKey = this.Index + 1
	point := &UprobeArgs{}
	point.Index = uint32(index)
	// 这样标记为需要从这里取出寄存器
	point.EnterKey = this.EnterKey
	point.LibPath = this.LibPath
	point.RealFilePath = this.RealFilePath
	point.Name = fmt.Sprintf("0x%x", this.ExitOffset)
	point.Symbol = ""
	point.Offset = this.ExitOffset
	point.NonElfOffset = this.NonElfOffset
	point.ArgsStr = this.ArgsStr
	point.PointArgs = this.PointArgs
	point.KillSignal = this.KillSignal
	return point
}

func (this *UprobeArgs) GetConfig() UprobePointOpKeyConfig {
	config := UprobePointOpKeyConfig{}
	config.EnterKey = this.EnterKey
	config.Signal = this.KillSignal
	for _, point_arg := range this.PointArgs {
		config.AddPointArg(point_arg)
	}
	// this.DumpOpList("uprobe_"+this.Name, config.OpKeyList[:])
	return config
}

func (this *UprobeArgs) DumpOpList(tag string, op_list []uint32) {
	fmt.Printf("[DumpOpList] %s Name:%s Count:%d\n", tag, this.Name, len(op_list))
	for index, op_index := range op_list {
		if op_index == 0 {
			continue
		}
		fmt.Printf("idx:%3d op_key:%3d %s\n", index, op_index, argtype.OPM.GetOpInfo(op_index))
	}
}

func (this *UprobeArgs) GetPath() string {
	if this.NonElfOffset > 0 {
		items := strings.Split(this.LibPath, "/")
		path := this.RealFilePath + "!" + items[len(items)-1]
		return fmt.Sprintf("%s(0x%x)", path, this.NonElfOffset)
	} else {
		return this.LibPath
	}
}

func (this *UprobeArgs) String() string {
	if this.Symbol == "" {
		return fmt.Sprintf("[%s + 0x%x] %s", this.GetPath(), this.Offset, this.ArgsStr)
	} else {
		return fmt.Sprintf("[%s] -> sym:%s off:0x%x %s", this.GetPath(), this.Symbol, this.Offset, this.ArgsStr)
	}
}
