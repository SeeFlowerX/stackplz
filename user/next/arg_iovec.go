package next

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

type ARG_IOVEC struct {
	ArgType
}

func (this *ARG_IOVEC) SetupRegAsLoopCount(reg_index uint32) IArgType {
	at := ARG_IOVEC{}
	at.Name = this.Name
	at.Alias = this.Alias
	at.Size = this.Size
	t := syscall.Iovec{}
	op := BuildReadRegBreakCount(uint64(reg_index))
	at.AddOp(OPM.AddOp(op))
	at.AddOp(OPC_SAVE_REG)
	at.AddOp(OPC_FOR_BREAK)
	at.AddOp(OPC_SET_TMP_VALUE)
	at.Setup()
	at.AddOp(OPC_MOVE_TMP_VALUE)
	at.AddOp(OPC_ADD_OFFSET.NewValue(uint64(unsafe.Sizeof(t))))
	at.AddOp(OPC_FOR_BREAK)
	return &at
}

func (this *ARG_IOVEC) Setup() {
	t := syscall.Iovec{}
	this.SetupSaveStruct()
	this.AddOp(OPC_SET_READ_LEN.NewValue(uint64(MAX_BUF_READ_SIZE)))
	this.AddOp(BuildReadPtrLen(uint64(unsafe.Offsetof(t.Len))))
	this.AddOp(OPC_READ_POINTER)
	this.AddOp(OPC_MOVE_POINTER_VALUE)
	this.AddOp(OPC_SAVE_STRUCT)
}

func (this *ARG_IOVEC) Parse(ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	if !parse_more {
		return fmt.Sprintf("0x%x", ptr)
	}
	var iovcnt Arg_reg
	if err := binary.Read(buf, binary.LittleEndian, &iovcnt); err != nil {
		panic(err)
	}
	var iov_read_count int = MAX_IOV_COUNT
	if int(iovcnt.Address) < iov_read_count {
		iov_read_count = int(iovcnt.Address)
	}
	var result []string
	for i := 0; i < iov_read_count; i++ {
		var arg_iovec Arg_Iovec_Fix_t
		if err := binary.Read(buf, binary.LittleEndian, &arg_iovec.Arg_Iovec_Fix); err != nil {
			panic(err)
		}
		var iov_buf Arg_str
		if err := binary.Read(buf, binary.LittleEndian, &iov_buf); err != nil {
			panic(err)
		}
		payload := make([]byte, iov_buf.Len)
		if err := binary.Read(buf, binary.LittleEndian, &payload); err != nil {
			panic(err)
		}
		arg_iovec.Payload = payload
		result = append(result, fmt.Sprintf("iov_%d=%s", i, arg_iovec.Format()))
	}
	iov_dump := "\n\t" + strings.Join(result, "\n\t") + "\n"
	return fmt.Sprintf("0x%x(%s)", ptr, iov_dump)
}

func RegAsIovecLoopCount(p IArgType, reg_index uint32) IArgType {
	at, ok := (p).(*ARG_IOVEC)
	if !ok {
		panic("...")
	}
	return at.SetupRegAsLoopCount(reg_index)
}

func init() {
	Register(&ARG_IOVEC{}, "iovec", TYPE_IOVEC, uint32(unsafe.Sizeof(syscall.Iovec{})))
}
