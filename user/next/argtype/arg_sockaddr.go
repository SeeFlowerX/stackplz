package argtype

// type ARG_SOCKADDR struct {
// 	ARG_STRUCT
// }

// func (this *ARG_SOCKADDR) Setup() {
// 	this.ARG_STRUCT.Setup()
// }

// func (this *ARG_SOCKADDR) Parse(ptr uint64, buf *bytes.Buffer, parse_more bool) string {
// 	if !parse_more {
// 		return fmt.Sprintf("0x%x", ptr)
// 	}
// 	var arg Arg_RawSockaddrUnix
// 	if err := binary.Read(buf, binary.LittleEndian, &arg.Index); err != nil {
// 		panic(err)
// 	}
// 	if err := binary.Read(buf, binary.LittleEndian, &arg.Len); err != nil {
// 		panic(err)
// 	}
// 	if arg.Len > 0 {
// 		if err := binary.Read(buf, binary.LittleEndian, &arg.RawSockaddrUnix); err != nil {
// 			panic(err)
// 		}
// 		return fmt.Sprintf("0x%x%s", ptr, arg.Format())
// 	}
// 	return fmt.Sprintf("0x%x", ptr)
// }

// func init() {
// 	Register(&ARG_SOCKADDR{}, "sockaddr", TYPE_SOCKADDR, uint32(unsafe.Sizeof(syscall.RawSockaddrUnix{})))
// }
