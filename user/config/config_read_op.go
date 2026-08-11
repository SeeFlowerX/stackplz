package config

import (
	"fmt"
	"strconv"
	"strings"

	"stackplz/user/argtype"
	. "stackplz/user/common"
)

func addReadOp(pointArg *PointArg, readOp string) {
	if readOp == "" {
		return
	}

	hasFirstOp := false
	for ptrIdx, opStr := range strings.Split(readOp, ".") {
		if ptrIdx > 0 {
			readPtrOp, rest := parsePointerReadOp(opStr)
			pointArg.AddExtraOp(readPtrOp)
			pointArg.AddExtraOp(argtype.OPC_MOVE_POINTER_VALUE)
			opStr = rest
		}
		if opStr == "" {
			continue
		}
		v := opStr + "+"
		lastOp := ""
		for {
			i := strings.IndexAny(v, "+-")
			if i < 0 {
				break
			}
			op := string(v[i])
			token := string(v[0:i])
			v = v[i+1:]
			if token != "" {
				if value, err := strconv.ParseUint(token, 0, 64); err == nil {
					if !hasFirstOp {
						panic(fmt.Sprintf("first op must be reg"))
					}
					if lastOp == "-" {
						pointArg.AddExtraOp(argtype.OPC_SUB_OFFSET.NewValue(value))
					} else {
						pointArg.AddExtraOp(argtype.OPC_ADD_OFFSET.NewValue(value))
					}
				} else {
					regIndex := GetRegIndex(token)
					pointArg.AddExtraOp(argtype.Add_READ_MOVE_REG(uint64(regIndex)))
					if hasFirstOp {
						if lastOp == "-" {
							pointArg.AddExtraOp(argtype.OPC_SUB_REG)
						} else {
							pointArg.AddExtraOp(argtype.OPC_ADD_REG)
						}
					}
					if !hasFirstOp {
						hasFirstOp = true
					}
				}
			}
			lastOp = op
		}
	}
	pointArg.AddExtraOp(argtype.OPC_SAVE_ADDR)
}

func parsePointerReadOp(opStr string) (*argtype.OpConfig, string) {
	switch {
	case opStr == "ptr32" || strings.HasPrefix(opStr, "ptr32+") || strings.HasPrefix(opStr, "ptr32-"):
		return argtype.OPC_READ_POINTER32, strings.TrimPrefix(opStr, "ptr32")
	case opStr == "ptr64" || strings.HasPrefix(opStr, "ptr64+") || strings.HasPrefix(opStr, "ptr64-"):
		return argtype.OPC_READ_POINTER64, strings.TrimPrefix(opStr, "ptr64")
	default:
		return argtype.OPC_READ_POINTER, opStr
	}
}
