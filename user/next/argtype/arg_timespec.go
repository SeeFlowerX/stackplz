package argtype

// type ARG_TIMESPEC struct {
// 	ARG_STRUCT
// }

// func (this *ARG_TIMESPEC) Setup() {
// 	this.ARG_STRUCT.Setup()
// }

// func (this *ARG_TIMESPEC) Parse(ptr uint64, buf *bytes.Buffer, parse_more bool) string {
// 	if !parse_more {
// 		return fmt.Sprintf("0x%x", ptr)
// 	}
// 	if this.GetStructLen(buf) != 0 {
// 		var arg Arg_Timespec
// 		if err := binary.Read(buf, binary.LittleEndian, &arg.Timespec); err != nil {
// 			panic(err)
// 		}
// 		return fmt.Sprintf("0x%x%s", ptr, arg.Format())
// 	}
// 	return fmt.Sprintf("0x%x", ptr)
// }

// func init() {
// 	Register(&ARG_TIMESPEC{}, "timespec", TYPE_TIMESPEC, uint32(unsafe.Sizeof(syscall.Timespec{})))
// }
