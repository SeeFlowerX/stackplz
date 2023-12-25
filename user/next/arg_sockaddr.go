package next

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"
)

type ARG_SOCKADDR struct {
	ArgType
}

func (this *ARG_SOCKADDR) Setup() {
	this.SetupSaveStruct()
}

func (this *ARG_SOCKADDR) Parse(ptr uint64, buf *bytes.Buffer) string {
	var arg Arg_str
	if err := binary.Read(buf, binary.LittleEndian, &arg); err != nil {
		panic(err)
	}
	var arg_sockaddr Arg_RawSockaddrUnix
	if arg.Len > 0 {
		if err := binary.Read(buf, binary.LittleEndian, &arg_sockaddr.RawSockaddrUnix); err != nil {
			panic(err)
		}
		return fmt.Sprintf("0x%x%s", ptr, arg_sockaddr.Format())
	}
	return fmt.Sprintf("0x%x", ptr)
	// return fmt.Sprintf("0x%x(%s)", ptr, this.ParseArgStruct(buf, &Arg_RawSockaddrUnix{}))
}

func init() {
	Register(&ARG_SOCKADDR{}, "sockaddr", TYPE_SOCKADDR, uint32(unsafe.Sizeof(syscall.RawSockaddrUnix{})))
}
