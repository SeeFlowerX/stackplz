package next

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

type ARG_MSGHDR struct {
	ARG_STRUCT
}

func (this *ARG_MSGHDR) Setup() {
	t := syscall.Msghdr{}
	this.ARG_STRUCT.Setup()
	this.AddOp(OPC_SET_TMP_VALUE)
	this.AddOp(OPC_SET_READ_LEN.NewValue(uint64(MAX_BUF_READ_SIZE)))
	this.AddOp(BuildReadPtrLen(uint64(unsafe.Offsetof(t.Controllen))))
	this.AddOp(BuildReadPtrAddr(uint64(unsafe.Offsetof(t.Control))))
	this.AddOp(OPC_SAVE_STRUCT)
	this.AddOp(OPC_MOVE_TMP_VALUE)
	this.AddOp(BuildReadPtrBreakCount(uint64(unsafe.Offsetof(t.Iovlen))))
	// 由于结构体直接可以取到长度 这里就不再保存一次了
	// AT_MSGHDR.AddOp(OPC_SAVE_POINTER)
	this.AddOp(BuildReadPtrAddr(uint64(unsafe.Offsetof(t.Iov))))
	this.AddOp(OPC_SET_TMP_VALUE)
	this.AddOp(OPC_FOR_BREAK)
	iovec := GetArgType("iovec")
	this.OpList = append(this.OpList, iovec.GetOpList()...)
	this.AddOp(OPC_MOVE_TMP_VALUE)
	this.AddOp(OPC_ADD_OFFSET.NewValue(uint64(iovec.GetSize())))
	this.AddOp(OPC_FOR_BREAK)
}

func (this *ARG_MSGHDR) Parse(ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	if !parse_more {
		return fmt.Sprintf("0x%x", ptr)
	}
	var arg_msghdr Arg_Msghdr
	if err := binary.Read(buf, binary.LittleEndian, &arg_msghdr); err != nil {
		panic(err)
	}
	var control_buf Arg_str
	if err := binary.Read(buf, binary.LittleEndian, &control_buf); err != nil {
		panic(err)
	}
	control_payload := []byte{}
	if control_buf.Len > 0 {
		control_payload = make([]byte, control_buf.Len)
		if err := binary.Read(buf, binary.LittleEndian, &control_payload); err != nil {
			panic(err)
		}
	}

	var iov_read_count int = MAX_IOV_COUNT
	if int(arg_msghdr.Iovlen) < iov_read_count {
		iov_read_count = int(arg_msghdr.Iovlen)
	}

	var iov_results []string
	for i := 0; i < iov_read_count; i++ {
		var arg_iovec Arg_Iovec_Fix_t
		if err := binary.Read(buf, binary.LittleEndian, &arg_iovec.Arg_Iovec_Fix); err != nil {
			panic(err)
		}
		// this.logger.Printf("index:%d iovec={%s}", arg_iovec.Index, arg_iovec.Format())

		var iov_buf Arg_str
		if err := binary.Read(buf, binary.LittleEndian, &iov_buf); err != nil {
			panic(err)
		}
		// this.logger.Printf("index:%d iov_buf.Len={%d}", iov_buf.Index, iov_buf.Len)
		payload := []byte{}
		if iov_buf.Len > 0 {
			payload = make([]byte, iov_buf.Len)
			if err := binary.Read(buf, binary.LittleEndian, &payload); err != nil {
				panic(err)
			}
		}
		arg_iovec.Payload = payload
		iov_results = append(iov_results, fmt.Sprintf("iov_%d=%s", i, arg_iovec.Format()))
	}
	fmt_str := "(\n\t" + strings.Join(iov_results, ", \n\t") + "\n)"
	return fmt.Sprintf("0x%x%s", ptr, arg_msghdr.FormatFull(fmt_str, control_buf.Format(control_payload)))
}

func init() {
	Register(&ARG_MSGHDR{}, "msghdr", TYPE_MSGHDR, uint32(unsafe.Sizeof(syscall.Msghdr{})))
}
