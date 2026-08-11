//go:build !forarm
// +build !forarm

package common

import "fmt"

const NativePointerSize = 8

func GetRegIndex(reg string) uint32 {
	value, ok := RegsNameMap[reg]
	if !ok {
		panic(fmt.Sprintf("ParseAsReg failed =>%s<=", reg))
	}
	return value
}
