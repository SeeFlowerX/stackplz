package event

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"

	"stackplz/user/argtype"
	"stackplz/user/common"
	"stackplz/user/config"
)

const maxStringReadSize = 16384

type brkArgReader struct {
	pid   uint32
	event *BrkEvent
	mem   *os.File
}

type brkOpCtx struct {
	saveIndex    uint8
	regIndex     uint8
	loopCount    uint8
	breakCount   uint8
	loopIndex    int
	opKeyIndex   int
	postCode     uint32
	readLen      uint32
	readAddr     uint64
	regValue     uint64
	pointerValue uint64
	tmpValue     uint64
	saved        bytes.Buffer
}

func newBrkArgReader(pid uint32, event *BrkEvent) *brkArgReader {
	return &brkArgReader{pid: pid, event: event}
}

func (this *brkArgReader) Close() {
	if this.mem != nil {
		this.mem.Close()
		this.mem = nil
	}
}

func (this *brkArgReader) formatArgs(pointArgs []*config.PointArg) string {
	if len(pointArgs) == 0 {
		return ""
	}
	defer this.Close()

	results := make([]string, 0, len(pointArgs))
	for _, pointArg := range pointArgs {
		result, err := this.formatArg(pointArg)
		if err != nil {
			result = fmt.Sprintf("<read_error:%v>", err)
		}
		results = append(results, fmt.Sprintf("%s=%s", pointArg.Name, result))
	}
	return "(" + strings.Join(results, ", ") + ")"
}

func (this *brkArgReader) formatArg(pointArg *config.PointArg) (result string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()

	raw, err := this.runPointArg(pointArg)
	if err != nil {
		return "", err
	}
	buf := bytes.NewBuffer(raw)
	var ptr argtype.Arg_reg
	if err := binary.Read(buf, binary.LittleEndian, &ptr); err != nil {
		return "", err
	}
	return pointArg.Parse(ptr.Address, buf, config.EBPF_UPROBE_ENTER), nil
}

func (this *brkArgReader) runPointArg(pointArg *config.PointArg) ([]byte, error) {
	ctx := &brkOpCtx{saveIndex: 0, opKeyIndex: 0, postCode: argtype.OP_SKIP}
	opKeys := pointArg.GetOpList()
	var currentOp *argtype.OpConfig

	for i := 0; i < common.MAX_OP_COUNT; i++ {
		var code uint32
		if currentOp != nil && ctx.postCode != argtype.OP_SKIP {
			code = ctx.postCode
			ctx.postCode = argtype.OP_SKIP
		} else {
			if ctx.opKeyIndex >= len(opKeys) {
				break
			}
			currentOp = argtype.OPM.GetOp(opKeys[ctx.opKeyIndex])
			ctx.opKeyIndex++
			code = currentOp.Code
			ctx.postCode = currentOp.PostCode
		}

		if code == argtype.OP_SKIP {
			break
		}
		this.runOp(ctx, currentOp, code)
	}

	if ctx.saved.Len() == 0 {
		return nil, fmt.Errorf("no brk arg data saved")
	}
	return ctx.saved.Bytes(), nil
}

func (this *brkArgReader) runOp(ctx *brkOpCtx, op *argtype.OpConfig, code uint32) {
	switch code {
	case argtype.OP_RESET_CTX:
		ctx.breakCount = 0
		ctx.regIndex = 0
		ctx.readAddr = 0
		ctx.readLen = 0
		ctx.regValue = 0
		ctx.pointerValue = 0
	case argtype.OP_SET_REG_INDEX:
		ctx.regIndex = uint8(op.Value)
	case argtype.OP_SET_READ_LEN:
		ctx.readLen = uint32(op.Value)
	case argtype.OP_SET_READ_LEN_REG_VALUE:
		if uint64(ctx.readLen) > ctx.regValue {
			ctx.readLen = uint32(ctx.regValue)
		}
	case argtype.OP_SET_READ_LEN_POINTER_VALUE:
		if uint64(ctx.readLen) > ctx.pointerValue {
			ctx.readLen = uint32(ctx.pointerValue)
		}
	case argtype.OP_SET_READ_COUNT:
		ctx.readLen *= uint32(op.Value)
	case argtype.OP_ADD_OFFSET:
		ctx.readAddr += op.Value
	case argtype.OP_SUB_OFFSET:
		ctx.readAddr -= op.Value
	case argtype.OP_MOVE_REG_VALUE:
		ctx.readAddr = ctx.regValue
	case argtype.OP_MOVE_POINTER_VALUE:
		ctx.readAddr = ctx.pointerValue
	case argtype.OP_MOVE_TMP_VALUE:
		ctx.readAddr = ctx.tmpValue
	case argtype.OP_SET_TMP_VALUE:
		ctx.tmpValue = ctx.readAddr
	case argtype.OP_FOR_BREAK:
		if ctx.loopCount == 0 {
			ctx.loopIndex = ctx.opKeyIndex
		}
		if ctx.loopCount >= ctx.breakCount {
			ctx.loopCount = 0
			ctx.breakCount = 0
			ctx.loopIndex = 0
		} else {
			ctx.loopCount++
			ctx.opKeyIndex = ctx.loopIndex
		}
	case argtype.OP_SET_BREAK_COUNT:
		ctx.breakCount = common.MAX_LOOP_COUNT
		if uint64(ctx.breakCount) > op.Value {
			ctx.breakCount = uint8(op.Value)
		}
	case argtype.OP_SET_BREAK_COUNT_REG_VALUE:
		ctx.breakCount = common.MAX_LOOP_COUNT
		if uint64(ctx.breakCount) > ctx.regValue {
			ctx.breakCount = uint8(ctx.regValue)
		}
	case argtype.OP_SET_BREAK_COUNT_POINTER_VALUE:
		ctx.breakCount = common.MAX_LOOP_COUNT
		if uint64(ctx.breakCount) > ctx.pointerValue {
			ctx.breakCount = uint8(ctx.pointerValue)
		}
	case argtype.OP_SAVE_ADDR:
		ctx.saveValue(ctx.readAddr)
	case argtype.OP_ADD_REG:
		ctx.readAddr += ctx.regValue
	case argtype.OP_SUB_REG:
		ctx.readAddr -= ctx.regValue
	case argtype.OP_READ_REG:
		if op.PreCode == argtype.OP_SET_REG_INDEX {
			ctx.regIndex = uint8(op.Value)
		}
		ctx.regValue = this.regValue(uint32(ctx.regIndex))
	case argtype.OP_SAVE_REG:
		ctx.saveValue(ctx.regValue)
	case argtype.OP_READ_POINTER:
		addr := ctx.readAddr
		if op.PreCode == argtype.OP_ADD_OFFSET {
			addr += op.Value
		} else if op.PreCode == argtype.OP_SUB_OFFSET {
			addr -= op.Value
		}
		ctx.pointerValue = this.readPointer(addr)
	case argtype.OP_SAVE_POINTER:
		ctx.saveValue(ctx.pointerValue)
	case argtype.OP_SAVE_STRUCT:
		ctx.readAddr = fixUserAddr(ctx.readAddr)
		if op.PreCode == argtype.OP_SET_READ_COUNT {
			ctx.readLen *= uint32(op.Value)
		}
		if ctx.readLen > common.MAX_BUF_READ_SIZE {
			ctx.readLen = common.MAX_BUF_READ_SIZE
		}
		payload, err := this.readMemory(ctx.readAddr, ctx.readLen)
		if err != nil {
			payload = nil
		}
		ctx.saveBytes(payload, uint32(len(payload)))
	case argtype.OP_SAVE_STRING:
		ctx.readAddr = fixUserAddr(ctx.readAddr)
		payload, err := this.readString(ctx.readAddr)
		if err != nil {
			payload = nil
		}
		ctx.saveBytes(payload, uint32(len(payload)))
	case argtype.OP_SAVE_PTR_STRING:
		ptr := this.readPointer(ctx.readAddr)
		ctx.saveValue(ptr)
		payload, err := this.readString(fixUserAddr(ptr))
		if ptr == 0 || err != nil {
			ctx.saveBytes(nil, common.STRARR_MAGIC_LEN)
			ctx.loopCount = ctx.breakCount
		} else {
			ctx.saveBytes(payload, uint32(len(payload)))
		}
	case argtype.OP_SAVE_STRING16:
		ctx.readAddr = fixUserAddr(ctx.readAddr)
		payload, err := this.readMemory(ctx.readAddr, common.MAX_BUF_READ_SIZE)
		if err != nil {
			payload = nil
		}
		ctx.saveBytes(payload, uint32(len(payload)))
	case argtype.OP_SAVE_PTR_STRING16:
		ptr := this.readPointer(ctx.readAddr)
		ctx.saveValue(ptr)
		payload, err := this.readMemory(fixUserAddr(ptr), common.MAX_BUF_READ_SIZE)
		if ptr == 0 || err != nil {
			ctx.saveBytes(nil, common.STRARR_MAGIC_LEN)
			ctx.loopCount = ctx.breakCount
		} else {
			ctx.saveBytes(payload, uint32(len(payload)))
		}
	case argtype.OP_READ_STD_STRING:
		ptr := fixUserAddr(ctx.readAddr)
		value := this.readByte(ptr)
		if value&1 == 0 {
			ptr += 1
		} else {
			ptr += 16
			ptr = this.readPointer(ptr)
		}
		ctx.readAddr = ptr
	case argtype.OP_READ_IL2CPP_STRING:
		ctx.readAddr += 0x14
	case argtype.OP_FILTER_VALUE, argtype.OP_FILTER_BUFFER, argtype.OP_FILTER_STRING:
		// Brk arg capture runs after perf sample delivery, so filters are not
		// applied here. Keep the op as a no-op to preserve read formatting.
	default:
	}
}

func (ctx *brkOpCtx) saveValue(value uint64) {
	ctx.saved.WriteByte(ctx.saveIndex)
	_ = binary.Write(&ctx.saved, binary.LittleEndian, value)
	ctx.saveIndex++
}

func (ctx *brkOpCtx) saveBytes(payload []byte, savedLen uint32) {
	ctx.saved.WriteByte(ctx.saveIndex)
	_ = binary.Write(&ctx.saved, binary.LittleEndian, savedLen)
	if len(payload) > 0 {
		ctx.saved.Write(payload)
	}
	ctx.saveIndex++
}

func (this *brkArgReader) regValue(regIndex uint32) uint64 {
	var regs []uint64
	if this.event.rec.ExtraOptions.UnwindStack {
		regs = this.event.UnwindBuffer.Regs
	} else {
		regs = this.event.RegsBuffer.Regs
	}
	if int(regIndex) >= len(regs) {
		return 0
	}
	return regs[regIndex]
}

func (this *brkArgReader) readPointer(addr uint64) uint64 {
	ptrSize := uint32(8)
	if this.event.mconf.Is32Bit {
		ptrSize = 4
	}
	payload, err := this.readMemory(fixUserAddr(addr), ptrSize)
	if err != nil || uint32(len(payload)) != ptrSize {
		return 0
	}
	if ptrSize == 4 {
		return uint64(binary.LittleEndian.Uint32(payload))
	}
	return binary.LittleEndian.Uint64(payload)
}

func (this *brkArgReader) readByte(addr uint64) byte {
	payload, err := this.readMemory(addr, 1)
	if err != nil || len(payload) == 0 {
		return 0
	}
	return payload[0]
}

func (this *brkArgReader) readString(addr uint64) ([]byte, error) {
	addr = fixUserAddr(addr)
	if addr == 0 {
		return nil, fmt.Errorf("zero address")
	}
	if err := this.openMem(); err != nil {
		return nil, err
	}

	var payload []byte
	const chunkSize = 256
	for len(payload) < maxStringReadSize {
		remain := maxStringReadSize - len(payload)
		if remain > chunkSize {
			remain = chunkSize
		}
		chunk := make([]byte, remain)
		n, err := this.mem.ReadAt(chunk, int64(addr)+int64(len(payload)))
		if n > 0 {
			payload = append(payload, chunk[:n]...)
			if idx := bytes.IndexByte(chunk[:n], 0); idx >= 0 {
				return payload[:len(payload)-n+idx+1], nil
			}
		}
		if err != nil {
			if len(payload) > 0 {
				return payload, nil
			}
			return nil, err
		}
	}
	return payload, nil
}

func (this *brkArgReader) readMemory(addr uint64, size uint32) ([]byte, error) {
	if size == 0 {
		return []byte{}, nil
	}
	if addr == 0 {
		return nil, fmt.Errorf("zero address")
	}
	if err := this.openMem(); err != nil {
		return nil, err
	}
	payload := make([]byte, size)
	n, err := this.mem.ReadAt(payload, int64(addr))
	if err != nil && err != io.EOF {
		if n > 0 {
			return payload[:n], err
		}
		return nil, err
	}
	return payload[:n], err
}

func (this *brkArgReader) openMem() error {
	if this.mem != nil {
		return nil
	}
	mem, err := os.Open(fmt.Sprintf("/proc/%d/mem", this.pid))
	if err != nil {
		return err
	}
	this.mem = mem
	return nil
}

func fixUserAddr(addr uint64) uint64 {
	return addr & 0xffffffffffff
}
