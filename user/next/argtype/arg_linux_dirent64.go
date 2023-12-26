package argtype

// type ARG_LINUX_DIRENT64 struct {
// 	ARG_STRUCT
// }

// func (this *ARG_LINUX_DIRENT64) Setup() {
// 	this.ARG_STRUCT.Setup()
// }

// func (this *ARG_LINUX_DIRENT64) Parse(ptr uint64, buf *bytes.Buffer, parse_more bool) string {
// 	if !parse_more {
// 		return fmt.Sprintf("0x%x", ptr)
// 	}
// 	if this.GetStructLen(buf) != 0 {
// 		var arg Dirent
// 		if err := binary.Read(buf, binary.LittleEndian, &arg); err != nil {
// 			panic(err)
// 		}
// 		var fields []string
// 		fields = append(fields, fmt.Sprintf("ino=%d", arg.Ino))
// 		fields = append(fields, fmt.Sprintf("off=%d", arg.Off))
// 		fields = append(fields, fmt.Sprintf("reclen=%d", arg.Reclen))
// 		fields = append(fields, fmt.Sprintf("type=%d", arg.Type))
// 		fields = append(fields, fmt.Sprintf("name=%s", util.PrettyByteSlice(arg.Name[:arg.Reclen])))
// 		return fmt.Sprintf("0x%x(%s)", ptr, strings.Join(fields, ", "))
// 		// return fmt.Sprintf("0x%x(\n%s)", ptr, this.DumpBuffer(buf))
// 	}
// 	return fmt.Sprintf("0x%x", ptr)
// }

// func init() {
// 	Register(&ARG_LINUX_DIRENT64{}, "dirent", TYPE_DIRENT, uint32(unsafe.Sizeof(Dirent{})))
// }
