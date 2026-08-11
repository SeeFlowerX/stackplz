package config

import (
	"testing"

	"stackplz/user/argtype"
	. "stackplz/user/common"
)

func TestAddReadOpPointerWidth(t *testing.T) {
	tests := []struct {
		name       string
		readOp     string
		pointerOp  uint32
		offsets    []uint64
		offsetOps  []uint32
		terminalOp uint32
	}{
		{
			name:       "native pointer deref",
			readOp:     "sp+0x8.+0x10",
			pointerOp:  argtype.OP_READ_POINTER,
			offsets:    []uint64{0x8, 0x10},
			offsetOps:  []uint32{argtype.OP_ADD_OFFSET, argtype.OP_ADD_OFFSET},
			terminalOp: argtype.OP_SAVE_ADDR,
		},
		{
			name:       "explicit ptr32 deref",
			readOp:     "sp+0x8.ptr32+0x10",
			pointerOp:  argtype.OP_READ_POINTER32,
			offsets:    []uint64{0x8, 0x10},
			offsetOps:  []uint32{argtype.OP_ADD_OFFSET, argtype.OP_ADD_OFFSET},
			terminalOp: argtype.OP_SAVE_ADDR,
		},
		{
			name:       "explicit ptr64 deref with negative offset",
			readOp:     "sp+0x8.ptr64-0x4+0x20",
			pointerOp:  argtype.OP_READ_POINTER64,
			offsets:    []uint64{0x8, 0x4, 0x20},
			offsetOps:  []uint32{argtype.OP_ADD_OFFSET, argtype.OP_SUB_OFFSET, argtype.OP_ADD_OFFSET},
			terminalOp: argtype.OP_SAVE_ADDR,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pointArg := NewUprobePointArg("arg_0", POINTER, 0)
			addReadOp(pointArg, tt.readOp)
			ops := opConfigs(pointArg.ExtraOpList)

			if len(ops) < 6 {
				t.Fatalf("expected at least 6 ops, got %d", len(ops))
			}
			if ops[0].Code != argtype.OP_READ_REG || ops[0].PostCode != argtype.OP_MOVE_REG_VALUE {
				t.Fatalf("first op = %+v, want READ_REG/MOVE_REG_VALUE", ops[0])
			}
			if ops[2].Code != tt.pointerOp {
				t.Fatalf("pointer op = %s, want %s", argtype.OPM.GetOpName(ops[2].Code), argtype.OPM.GetOpName(tt.pointerOp))
			}
			if ops[3].Code != argtype.OP_MOVE_POINTER_VALUE {
				t.Fatalf("post pointer op = %s, want MOVE_POINTER_VALUE", argtype.OPM.GetOpName(ops[3].Code))
			}
			if ops[len(ops)-1].Code != tt.terminalOp {
				t.Fatalf("terminal op = %s, want %s", argtype.OPM.GetOpName(ops[len(ops)-1].Code), argtype.OPM.GetOpName(tt.terminalOp))
			}

			offsetIndex := 0
			for _, op := range ops {
				if op.Code != argtype.OP_ADD_OFFSET && op.Code != argtype.OP_SUB_OFFSET {
					continue
				}
				if offsetIndex >= len(tt.offsets) {
					t.Fatalf("unexpected extra offset op: %+v", op)
				}
				if op.Code != tt.offsetOps[offsetIndex] || op.Value != tt.offsets[offsetIndex] {
					t.Fatalf("offset op %d = %+v, want code=%s value=0x%x", offsetIndex, op, argtype.OPM.GetOpName(tt.offsetOps[offsetIndex]), tt.offsets[offsetIndex])
				}
				offsetIndex++
			}
			if offsetIndex != len(tt.offsets) {
				t.Fatalf("matched %d offset ops, want %d", offsetIndex, len(tt.offsets))
			}
		})
	}
}

func opConfigs(opKeys []uint32) []*argtype.OpConfig {
	ops := make([]*argtype.OpConfig, 0, len(opKeys))
	for _, opKey := range opKeys {
		ops = append(ops, argtype.OPM.GetOp(opKey))
	}
	return ops
}
