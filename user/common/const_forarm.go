//go:build forarm
// +build forarm

package common

import "fmt"

func GetRegIndex(reg string) uint32 {
	value, ok := RegsArmNameMap[reg]
	if !ok {
		panic(fmt.Sprintf("ParseAsReg failed =>%s<=", reg))
	}
	return value
}
