package argtype

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	. "stackplz/user/next/common"
	"stackplz/user/util"
	"strings"
	"syscall"
	"unsafe"
)

// 这里是一些列基础参数的组合生成

func parse_STRING(ctx IArgType, ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	if !parse_more {
		return fmt.Sprintf("0x%x", ptr)
	}

	var arg Arg_str
	if err := binary.Read(buf, binary.LittleEndian, &arg); err != nil {
		panic(err)
	}
	payload := make([]byte, arg.Len)
	if err := binary.Read(buf, binary.LittleEndian, &payload); err != nil {
		panic(err)
	}
	return fmt.Sprintf("0x%x(%s)", ptr, util.B2STrim(payload))
}

func r_STRING() IArgType {
	at := RegisterPre("string", STRING, STRUCT)
	at.AddOp(OPC_SAVE_STRING)
	at.SetParseCB(parse_STRING)
	return at
}

func parse_STRING_ARRAY(ctx IArgType, ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	if !parse_more {
		return fmt.Sprintf("0x%x", ptr)
	}
	var results []string
	for i := 0; i < int(MAX_LOOP_COUNT); i++ {
		var str_addr Arg_reg
		if err := binary.Read(buf, binary.LittleEndian, &str_addr); err != nil {
			panic(err)
		}
		var arg_str Arg_str
		if err := binary.Read(buf, binary.LittleEndian, &arg_str); err != nil {
			panic(err)
		}
		payload := make([]byte, arg_str.Len)
		if err := binary.Read(buf, binary.LittleEndian, &payload); err != nil {
			panic(err)
		}
		if str_addr.Address == 0 {
			break
		}
		result := fmt.Sprintf("0x%x(%s)", str_addr.Address, util.B2STrim(payload))
		results = append(results, result)
	}
	return fmt.Sprintf("0x%x[%s]", ptr, "\n\t"+strings.Join(results, ",\n\t")+"\n")
}

func r_STRING_ARRAY() IArgType {
	at := RegisterNew("string_array", STRUCT)
	at.AddOp(OPC_SET_BREAK_COUNT.NewValue(uint64(MAX_LOOP_COUNT)))
	at.AddOp(OPC_FOR_BREAK)
	at.AddOp(OPC_SAVE_PTR_STRING)
	at.AddOp(OPC_ADD_OFFSET.NewValue(uint64(unsafe.Sizeof(8))))
	at.AddOp(OPC_FOR_BREAK)
	at.SetParseCB(parse_STRING_ARRAY)
	return at
}

func parse_ARRAY(ctx IArgType, ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	if !parse_more {
		return fmt.Sprintf("0x%x", ptr)
	}
	p := (ctx).(*ARG_ARRAY)
	if p.GetStructLen(buf) == 0 {
		return fmt.Sprintf("0x%x[]", ptr)
	}
	var results []string
	switch p.ArrayArgType.(type) {
	case *ARG_INT:
		var arg []int32 = make([]int32, p.ArrayLen)
		if err := binary.Read(buf, binary.LittleEndian, &arg); err != nil {
			panic(err)
		}
		for _, v := range arg {
			result := p.ArrayArgType.Parse(uint64(v), buf, parse_more)
			results = append(results, result)
		}
		break
	case *ARG_UINT:
		var arg []uint32 = make([]uint32, p.ArrayLen)
		if err := binary.Read(buf, binary.LittleEndian, &arg); err != nil {
			panic(err)
		}
		for _, v := range arg {
			result := p.ArrayArgType.Parse(uint64(v), buf, parse_more)
			results = append(results, result)
		}
		break
	case *ARG_INT32:
		var arg []int32 = make([]int32, p.ArrayLen)
		if err := binary.Read(buf, binary.LittleEndian, &arg); err != nil {
			panic(err)
		}
		for _, v := range arg {
			result := p.ArrayArgType.Parse(uint64(v), buf, parse_more)
			results = append(results, result)
		}
		break
	default:
		panic(fmt.Sprintf("parse method for %s array not impl", reflect.TypeOf(p.ArrayArgType)))
	}
	return fmt.Sprintf("0x%x[%s]", ptr, strings.Join(results, ", "))
}

func r_PRE_ARRAY(p IArgType, type_index, array_len uint32) IArgType {
	// 这里用于生成内置定义了的 type_index 数组
	array_name := fmt.Sprintf("array_%s_%d", p.GetName(), array_len)
	new_p := RegisterPre(array_name, type_index, ARRAY)
	new_i, ok := (new_p).(IArgTypeArray)
	if !ok {
		panic("...")
	}
	new_i.SetArrayLen(array_len)
	new_i.SetArrayArgType(p)
	// 更新操作似乎是不需要的 需要实际测试
	// UpdateArgType(new_p)
	// 直接保存对应的数据 即 元素大小 * 元素个数
	new_p.AddOp(SaveStruct(uint64(new_p.GetSize())))
	new_p.SetParseCB(parse_ARRAY)
	return new_p
}

// func r_ARRAY(p IArgType, array_len uint32) IArgType {
// 	array_name := fmt.Sprintf("array_%s_%d", p.GetName(), array_len)
// 	new_p := RegisterNew(array_name, ARRAY)
// 	new_i, ok := (new_p).(IArgTypeArray)
// 	if !ok {
// 		panic("...")
// 	}
// 	new_i.SetArrayLen(array_len)
// 	new_i.SetArrayArgType(p)
// 	new_p.AddOp(SaveStruct(uint64(p.GetSize() * array_len)))
// 	new_p.SetParseCB(parse_ARRAY)
// 	return new_p
// }

func parse_ITTMERSPEC(ctx IArgType, ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	if !parse_more {
		return fmt.Sprintf("0x%x", ptr)
	}
	if (ctx).(*ARG_STRUCT).GetStructLen(buf) != 0 {
		var arg Arg_ItTmerspec
		if err := binary.Read(buf, binary.LittleEndian, &arg.ItTmerspec); err != nil {
			panic(err)
		}
		return fmt.Sprintf("0x%x%s", ptr, arg.Format())
	}
	return fmt.Sprintf("0x%x", ptr)
}

func r_ITTMERSPEC() IArgType {
	at := RegisterNew("ittmerspec", STRUCT)
	at.SetSize(uint32(unsafe.Sizeof(ItTmerspec{})))
	at.AddOp(OPC_SET_READ_LEN.NewValue(uint64(at.GetSize())))
	at.AddOp(OPC_SAVE_STRUCT)
	at.SetParseCB(parse_ITTMERSPEC)
	return at
}

func parse_RUSAGE(ctx IArgType, ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	if !parse_more {
		return fmt.Sprintf("0x%x", ptr)
	}
	if (ctx).(*ARG_STRUCT).GetStructLen(buf) != 0 {
		var arg Arg_Rusage
		if err := binary.Read(buf, binary.LittleEndian, &arg.Rusage); err != nil {
			panic(err)
		}
		return fmt.Sprintf("0x%x%s", ptr, arg.Format())
	}
	return fmt.Sprintf("0x%x", ptr)
}

func r_RUSAGE() IArgType {
	at := RegisterNew("rusage", STRUCT)
	at.SetSize(uint32(unsafe.Sizeof(syscall.Rusage{})))
	at.AddOp(OPC_SET_READ_LEN.NewValue(uint64(at.GetSize())))
	at.AddOp(OPC_SAVE_STRUCT)
	at.SetParseCB(parse_RUSAGE)
	return at
}

func parse_UTSNAME(ctx IArgType, ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	if !parse_more {
		return fmt.Sprintf("0x%x", ptr)
	}
	if (ctx).(*ARG_STRUCT).GetStructLen(buf) != 0 {
		var arg Arg_Utsname
		if err := binary.Read(buf, binary.LittleEndian, &arg.Utsname); err != nil {
			panic(err)
		}
		return fmt.Sprintf("0x%x%s", ptr, arg.Format())
	}
	return fmt.Sprintf("0x%x", ptr)
}

func r_UTSNAME() IArgType {
	at := RegisterNew("utsname", STRUCT)
	at.SetSize(uint32(unsafe.Sizeof(syscall.Utsname{})))
	at.AddOp(OPC_SET_READ_LEN.NewValue(uint64(at.GetSize())))
	at.AddOp(OPC_SAVE_STRUCT)
	at.SetParseCB(parse_UTSNAME)
	return at
}

func parse_TIMEVAL(ctx IArgType, ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	if !parse_more {
		return fmt.Sprintf("0x%x", ptr)
	}
	if (ctx).(*ARG_STRUCT).GetStructLen(buf) != 0 {
		var arg Arg_Timeval
		if err := binary.Read(buf, binary.LittleEndian, &arg.Timeval); err != nil {
			panic(err)
		}
		return fmt.Sprintf("0x%x%s", ptr, arg.Format())
	}
	return fmt.Sprintf("0x%x", ptr)
}

func r_TIMEVAL() IArgType {
	at := RegisterNew("timeval", STRUCT)
	at.SetSize(uint32(unsafe.Sizeof(syscall.Timeval{})))
	at.AddOp(OPC_SET_READ_LEN.NewValue(uint64(at.GetSize())))
	at.AddOp(OPC_SAVE_STRUCT)
	at.SetParseCB(parse_TIMEVAL)
	return at
}

func parse_TIMEZONE(ctx IArgType, ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	if !parse_more {
		return fmt.Sprintf("0x%x", ptr)
	}
	if (ctx).(*ARG_STRUCT).GetStructLen(buf) != 0 {
		var arg Arg_TimeZone_t
		if err := binary.Read(buf, binary.LittleEndian, &arg.TimeZone_t); err != nil {
			panic(err)
		}
		return fmt.Sprintf("0x%x%s", ptr, arg.Format())
	}
	return fmt.Sprintf("0x%x", ptr)
}

func r_TIMEZONE() IArgType {
	at := RegisterNew("timezone", STRUCT)
	at.SetSize(uint32(unsafe.Sizeof(TimeZone_t{})))
	at.AddOp(OPC_SET_READ_LEN.NewValue(uint64(at.GetSize())))
	at.AddOp(OPC_SAVE_STRUCT)
	at.SetParseCB(parse_TIMEZONE)
	return at
}

func parse_SYSINFO(ctx IArgType, ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	if !parse_more {
		return fmt.Sprintf("0x%x", ptr)
	}
	if (ctx).(*ARG_STRUCT).GetStructLen(buf) != 0 {
		var arg Arg_Sysinfo_t
		if err := binary.Read(buf, binary.LittleEndian, &arg.Sysinfo_t); err != nil {
			panic(err)
		}
		return fmt.Sprintf("0x%x%s", ptr, arg.Format())
	}
	return fmt.Sprintf("0x%x", ptr)
}

func r_SYSINFO() IArgType {
	at := RegisterNew("sysinfo", STRUCT)
	at.SetSize(uint32(unsafe.Sizeof(syscall.Sysinfo_t{})))
	at.AddOp(OPC_SET_READ_LEN.NewValue(uint64(at.GetSize())))
	at.AddOp(OPC_SAVE_STRUCT)
	at.SetParseCB(parse_SYSINFO)
	return at
}

func parse_STATFS(ctx IArgType, ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	if !parse_more {
		return fmt.Sprintf("0x%x", ptr)
	}
	if (ctx).(*ARG_STRUCT).GetStructLen(buf) != 0 {
		var arg Arg_Statfs_t
		if err := binary.Read(buf, binary.LittleEndian, &arg.Statfs_t); err != nil {
			panic(err)
		}
		return fmt.Sprintf("0x%x%s", ptr, arg.Format())
	}
	return fmt.Sprintf("0x%x", ptr)
}

func r_STATFS() IArgType {
	at := RegisterNew("statfs", STRUCT)
	at.SetSize(uint32(unsafe.Sizeof(syscall.Statfs_t{})))
	at.AddOp(OPC_SET_READ_LEN.NewValue(uint64(at.GetSize())))
	at.AddOp(OPC_SAVE_STRUCT)
	at.SetParseCB(parse_STATFS)
	return at
}

func parse_BUFFER(ctx IArgType, ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	if !parse_more {
		return fmt.Sprintf("0x%x", ptr)
	}
	var arg Arg_str
	if err := binary.Read(buf, binary.LittleEndian, &arg); err != nil {
		panic(err)
	}
	payload := make([]byte, arg.Len)
	if err := binary.Read(buf, binary.LittleEndian, &payload); err != nil {
		panic(err)
	}
	return fmt.Sprintf("0x%x%s", ptr, arg.Format(payload))
}

func r_BUFFER() IArgType {
	at := RegisterPre("buffer", BUFFER, STRUCT)
	at.AddOp(SaveStruct(uint64(MAX_BUF_READ_SIZE)))
	at.SetParseCB(parse_BUFFER)
	return at
}

func r_BUFFER_X2() IArgType {
	at := RegisterNew("buffer_x2", BUFFER)
	at.CleanOpList()
	at.AddOp(OPC_SET_READ_LEN.NewValue(uint64(MAX_BUF_READ_SIZE)))
	at.AddOp(BuildReadRegLen(uint64(REG_ARM64_X2)))
	at.AddOp(OPC_SAVE_STRUCT)
	return at
}

func r_BUFFER_LEN(length uint32) IArgType {
	at := RegisterNew(fmt.Sprintf("buffer_len_%d", length), BUFFER)
	at.SetSize(length)
	at.AddOp(OPC_SET_READ_LEN.NewValue(uint64(length)))
	at.AddOp(OPC_SAVE_STRUCT)
	return at
}

func parse_EPOLLEVENT(ctx IArgType, ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	if !parse_more {
		return fmt.Sprintf("0x%x", ptr)
	}
	if (ctx).(*ARG_STRUCT).GetStructLen(buf) != 0 {
		var arg Arg_EpollEvent
		if err := binary.Read(buf, binary.LittleEndian, &arg.EpollEvent); err != nil {
			panic(err)
		}
		return fmt.Sprintf("0x%x%s", ptr, arg.Format())
	}
	return fmt.Sprintf("0x%x", ptr)
}

func r_EPOLLEVENT() IArgType {
	at := RegisterNew("epoll_event", STRUCT)
	at.SetSize(uint32(unsafe.Sizeof(syscall.EpollEvent{})))
	at.AddOp(OPC_SET_READ_LEN.NewValue(uint64(at.GetSize())))
	at.AddOp(OPC_SAVE_STRUCT)
	at.SetParseCB(parse_EPOLLEVENT)
	return at
}

func parse_TIMESPEC(ctx IArgType, ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	if !parse_more {
		return fmt.Sprintf("0x%x", ptr)
	}
	if (ctx).(*ARG_STRUCT).GetStructLen(buf) != 0 {
		var arg Arg_Timespec
		if err := binary.Read(buf, binary.LittleEndian, &arg.Timespec); err != nil {
			panic(err)
		}
		return fmt.Sprintf("0x%x%s", ptr, arg.Format())
	}
	return fmt.Sprintf("0x%x", ptr)
}

func r_TIMESPEC() IArgType {
	at := RegisterNew("timespec", STRUCT)
	at.SetSize(uint32(unsafe.Sizeof(syscall.Timespec{})))
	at.AddOp(OPC_SET_READ_LEN.NewValue(uint64(at.GetSize())))
	at.AddOp(OPC_SAVE_STRUCT)
	at.SetParseCB(parse_TIMESPEC)
	return at
}

func parse_STAT(ctx IArgType, ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	if !parse_more {
		return fmt.Sprintf("0x%x", ptr)
	}
	if (ctx).(*ARG_STRUCT).GetStructLen(buf) != 0 {
		var arg Arg_Stat_t
		if err := binary.Read(buf, binary.LittleEndian, &arg.Stat_t); err != nil {
			panic(err)
		}
		return fmt.Sprintf("0x%x%s", ptr, arg.Format())
	}
	return fmt.Sprintf("0x%x", ptr)
}

func r_STAT() IArgType {
	at := RegisterNew("stat", STRUCT)
	at.SetSize(uint32(unsafe.Sizeof(syscall.Stat_t{})))
	at.AddOp(OPC_SET_READ_LEN.NewValue(uint64(at.GetSize())))
	at.AddOp(OPC_SAVE_STRUCT)
	at.SetParseCB(parse_STAT)
	return at
}

func parse_STACK_T(ctx IArgType, ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	if !parse_more {
		return fmt.Sprintf("0x%x", ptr)
	}
	if (ctx).(*ARG_STRUCT).GetStructLen(buf) != 0 {
		var arg Arg_Stack_t
		if err := binary.Read(buf, binary.LittleEndian, &arg.Stack_t); err != nil {
			panic(err)
		}
		return fmt.Sprintf("0x%x%s", ptr, arg.Format())
	}
	return fmt.Sprintf("0x%x", ptr)
}

func r_STACK_T() IArgType {
	at := RegisterNew("stack_t", STRUCT)
	at.SetSize(uint32(unsafe.Sizeof(Stack_t{})))
	at.AddOp(OPC_SET_READ_LEN.NewValue(uint64(at.GetSize())))
	at.AddOp(OPC_SAVE_STRUCT)
	at.SetParseCB(parse_STACK_T)
	return at
}

func parse_SOCKADDR(ctx IArgType, ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	if !parse_more {
		return fmt.Sprintf("0x%x", ptr)
	}
	if (ctx).(*ARG_STRUCT).GetStructLen(buf) != 0 {
		var arg Arg_RawSockaddrUnix
		if err := binary.Read(buf, binary.LittleEndian, &arg.RawSockaddrUnix); err != nil {
			panic(err)
		}
		return fmt.Sprintf("0x%x%s", ptr, arg.Format())
	}
	return fmt.Sprintf("0x%x", ptr)
}

func r_SOCKADDR() IArgType {
	at := RegisterNew("sockaddr", STRUCT)
	at.SetSize(uint32(unsafe.Sizeof(syscall.RawSockaddrUnix{})))
	at.AddOp(OPC_SET_READ_LEN.NewValue(uint64(at.GetSize())))
	at.AddOp(OPC_SAVE_STRUCT)
	at.SetParseCB(parse_SOCKADDR)
	return at
}

func parse_SIGINFO(ctx IArgType, ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	if !parse_more {
		return fmt.Sprintf("0x%x", ptr)
	}
	if (ctx).(*ARG_STRUCT).GetStructLen(buf) != 0 {
		var arg Arg_SigInfo
		if err := binary.Read(buf, binary.LittleEndian, &arg.SigInfo); err != nil {
			panic(err)
		}
		return fmt.Sprintf("0x%x%s", ptr, arg.Format())
	}
	return fmt.Sprintf("0x%x", ptr)
}

func r_SIGINFO() IArgType {
	at := RegisterNew("siginfo", STRUCT)
	at.SetSize(uint32(unsafe.Sizeof(SigInfo{})))
	at.AddOp(OPC_SET_READ_LEN.NewValue(uint64(at.GetSize())))
	at.AddOp(OPC_SAVE_STRUCT)
	at.SetParseCB(parse_SIGINFO)
	return at
}

func parse_SIGACTION(ctx IArgType, ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	if !parse_more {
		return fmt.Sprintf("0x%x", ptr)
	}
	if (ctx).(*ARG_STRUCT).GetStructLen(buf) != 0 {
		var arg Arg_Sigaction
		if err := binary.Read(buf, binary.LittleEndian, &arg.Sigaction); err != nil {
			panic(err)
		}
		return fmt.Sprintf("0x%x%s", ptr, arg.Format())
	}
	return fmt.Sprintf("0x%x", ptr)
}

func r_SIGACTION() IArgType {
	at := RegisterNew("sigaction", STRUCT)
	at.SetSize(uint32(unsafe.Sizeof(Sigaction{})))
	at.AddOp(OPC_SET_READ_LEN.NewValue(uint64(at.GetSize())))
	at.AddOp(OPC_SAVE_STRUCT)
	at.SetParseCB(parse_SIGACTION)
	return at
}

func parse_POLLFD(ctx IArgType, ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	if !parse_more {
		return fmt.Sprintf("0x%x", ptr)
	}
	if (ctx).(*ARG_STRUCT).GetStructLen(buf) != 0 {
		var arg Arg_Pollfd
		if err := binary.Read(buf, binary.LittleEndian, &arg.Pollfd); err != nil {
			panic(err)
		}
		return fmt.Sprintf("0x%x%s", ptr, arg.Format())
	}
	return fmt.Sprintf("0x%x", ptr)
}

func r_POLLFD() IArgType {
	at := RegisterNew("pollfd", STRUCT)
	at.SetSize(uint32(unsafe.Sizeof(Pollfd{})))
	at.AddOp(OPC_SET_READ_LEN.NewValue(uint64(at.GetSize())))
	at.AddOp(OPC_SAVE_STRUCT)
	at.SetParseCB(parse_POLLFD)
	return at
}

func parse_DIRENT(ctx IArgType, ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	if !parse_more {
		return fmt.Sprintf("0x%x", ptr)
	}
	if (ctx).(*ARG_STRUCT).GetStructLen(buf) != 0 {
		var arg Dirent
		if err := binary.Read(buf, binary.LittleEndian, &arg); err != nil {
			panic(err)
		}
		var fields []string
		fields = append(fields, fmt.Sprintf("ino=%d", arg.Ino))
		fields = append(fields, fmt.Sprintf("off=%d", arg.Off))
		fields = append(fields, fmt.Sprintf("reclen=%d", arg.Reclen))
		fields = append(fields, fmt.Sprintf("type=%d", arg.Type))
		fields = append(fields, fmt.Sprintf("name=%s", util.PrettyByteSlice(arg.Name[:arg.Reclen])))
		return fmt.Sprintf("0x%x(%s)", ptr, strings.Join(fields, ", "))
	}
	return fmt.Sprintf("0x%x", ptr)
}

func r_DIRENT() IArgType {
	at := RegisterNew("dirent", STRUCT)
	at.SetSize(uint32(unsafe.Sizeof(Dirent{})))
	at.AddOp(OPC_SET_READ_LEN.NewValue(uint64(at.GetSize())))
	at.AddOp(OPC_SAVE_STRUCT)
	at.SetParseCB(parse_POLLFD)
	return at
}

func parse_IOVEC(ctx IArgType, ptr uint64, buf *bytes.Buffer, parse_more bool) string {
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

func r_IOVEC() IArgType {
	t := syscall.Iovec{}
	at := RegisterPre("iovec", IOVEC, STRUCT)
	at.SetSize(uint32(unsafe.Sizeof(t)))
	at.AddOp(OPC_SET_READ_LEN.NewValue(uint64(at.GetSize())))
	at.AddOp(OPC_SAVE_STRUCT)
	at.AddOp(BuildReadPtrLen(uint64(unsafe.Offsetof(t.Len))))
	at.AddOp(OPC_READ_POINTER)
	at.AddOp(OPC_MOVE_POINTER_VALUE)
	at.AddOp(OPC_SAVE_STRUCT)
	// 这里解析单个 不一样 需要修正
	at.SetParseCB(parse_IOVEC)
	return at
}

func r_IOVEC_X2() IArgType {
	t := syscall.Iovec{}
	at := RegisterNew("iovec_x2", STRUCT)
	op := BuildReadRegBreakCount(uint64(REG_ARM64_X2))
	at.AddOp(OPM.AddOp(op))
	at.AddOp(OPC_SAVE_REG)
	at.AddOp(OPC_FOR_BREAK)
	at.AddOp(OPC_SET_TMP_VALUE)
	at.AddOpList(GetArgType(IOVEC))
	at.AddOp(OPC_MOVE_TMP_VALUE)
	at.AddOp(OPC_ADD_OFFSET.NewValue(uint64(unsafe.Sizeof(t))))
	at.AddOp(OPC_FOR_BREAK)
	at.SetParseCB(parse_IOVEC)
	return at
}

func parse_MSGHDR(ctx IArgType, ptr uint64, buf *bytes.Buffer, parse_more bool) string {
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

		var iov_buf Arg_str
		if err := binary.Read(buf, binary.LittleEndian, &iov_buf); err != nil {
			panic(err)
		}
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

func r_MSGHDR() IArgType {
	t := syscall.Msghdr{}
	at := RegisterPre("msghdr", MSGHDR, STRUCT)

	at.SetSize(uint32(unsafe.Sizeof(t)))
	at.AddOp(OPC_SET_READ_LEN.NewValue(uint64(at.GetSize())))
	at.AddOp(OPC_SAVE_STRUCT)
	at.AddOp(OPC_SET_TMP_VALUE)
	at.AddOp(OPC_SET_READ_LEN.NewValue(uint64(MAX_BUF_READ_SIZE)))
	at.AddOp(BuildReadPtrLen(uint64(unsafe.Offsetof(t.Controllen))))
	at.AddOp(BuildReadPtrAddr(uint64(unsafe.Offsetof(t.Control))))
	at.AddOp(OPC_SAVE_STRUCT)
	at.AddOp(OPC_MOVE_TMP_VALUE)
	at.AddOp(BuildReadPtrBreakCount(uint64(unsafe.Offsetof(t.Iovlen))))
	// 由于结构体直接可以取到长度 这里就不再保存一次了
	// at.AddOp(OPC_SAVE_POINTER)
	at.AddOp(BuildReadPtrAddr(uint64(unsafe.Offsetof(t.Iov))))
	at.AddOp(OPC_SET_TMP_VALUE)
	at.AddOp(OPC_FOR_BREAK)
	at_iovec := GetArgType(IOVEC)
	at.AddOpList(GetArgType(IOVEC))
	// iovec := GetArgType("iovec")
	// this.OpList = append(this.OpList, iovec.GetOpList()...)
	at.AddOp(OPC_MOVE_TMP_VALUE)
	at.AddOp(OPC_ADD_OFFSET.NewValue(uint64(at_iovec.GetSize())))
	at.AddOp(OPC_FOR_BREAK)
	at.SetParseCB(parse_MSGHDR)
	return at
}
