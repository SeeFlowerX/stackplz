package next

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"stackplz/user/util"
	"strings"
	"syscall"
	"unsafe"
)

// 这里是一些列基础参数的组合生成

func StringArrayParse(ctx IArgType, ptr uint64, buf *bytes.Buffer, parse_more bool) string {
	if !parse_more {
		return fmt.Sprintf("0x%x", ptr)
	}
	var results []string
	for i := 0; i < int(ctx.GetSize()); i++ {
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

func GetStrArr() IArgType {
	at := GetArgType("string").Clone()
	at.CleanOpList()
	at.AddOp(OPC_SET_BREAK_COUNT.NewValue(uint64(MAX_LOOP_COUNT)))
	at.AddOp(OPC_FOR_BREAK)
	at.AddOp(OPC_SAVE_PTR_STRING)
	at.AddOp(OPC_ADD_OFFSET.NewValue(uint64(unsafe.Sizeof(8))))
	at.AddOp(OPC_FOR_BREAK)
	at.SetParseCB(StringArrayParse)
	return at
}

func ItTmerspecParse(ctx IArgType, ptr uint64, buf *bytes.Buffer, parse_more bool) string {
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

func GetItTmerspec() IArgType {
	at := GetArgType("struct").Clone()
	at.CleanOpList()
	at.SetSize(uint32(unsafe.Sizeof(ItTmerspec{})))
	at.AddOp(OPC_SET_READ_LEN.NewValue(uint64(at.GetSize())))
	at.AddOp(OPC_SAVE_STRUCT)
	at.SetParseCB(ItTmerspecParse)
	return at
}

func RusageParse(ctx IArgType, ptr uint64, buf *bytes.Buffer, parse_more bool) string {
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

func GetRusage() IArgType {
	at := GetArgType("struct").Clone()
	at.CleanOpList()
	at.SetSize(uint32(unsafe.Sizeof(syscall.Rusage{})))
	at.AddOp(OPC_SET_READ_LEN.NewValue(uint64(at.GetSize())))
	at.AddOp(OPC_SAVE_STRUCT)
	at.SetParseCB(RusageParse)
	return at
}

func UtsnameParse(ctx IArgType, ptr uint64, buf *bytes.Buffer, parse_more bool) string {
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

func GetUtsname() IArgType {
	at := GetArgType("struct").Clone()
	at.CleanOpList()
	at.SetSize(uint32(unsafe.Sizeof(syscall.Utsname{})))
	at.AddOp(OPC_SET_READ_LEN.NewValue(uint64(at.GetSize())))
	at.AddOp(OPC_SAVE_STRUCT)
	at.SetParseCB(UtsnameParse)
	return at
}

func TimevalParse(ctx IArgType, ptr uint64, buf *bytes.Buffer, parse_more bool) string {
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

func GetTimeval() IArgType {
	at := GetArgType("struct").Clone()
	at.CleanOpList()
	at.SetSize(uint32(unsafe.Sizeof(syscall.Timeval{})))
	at.AddOp(OPC_SET_READ_LEN.NewValue(uint64(at.GetSize())))
	at.AddOp(OPC_SAVE_STRUCT)
	at.SetParseCB(TimevalParse)
	return at
}

func TimeZoneParse(ctx IArgType, ptr uint64, buf *bytes.Buffer, parse_more bool) string {
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

func GetTimeZone() IArgType {
	at := GetArgType("struct").Clone()
	at.CleanOpList()
	at.SetSize(uint32(unsafe.Sizeof(TimeZone_t{})))
	at.AddOp(OPC_SET_READ_LEN.NewValue(uint64(at.GetSize())))
	at.AddOp(OPC_SAVE_STRUCT)
	at.SetParseCB(TimeZoneParse)
	return at
}

func SysinfoParse(ctx IArgType, ptr uint64, buf *bytes.Buffer, parse_more bool) string {
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

func GetSysinfo() IArgType {
	at := GetArgType("struct").Clone()
	at.CleanOpList()
	at.SetSize(uint32(unsafe.Sizeof(syscall.Sysinfo_t{})))
	at.AddOp(OPC_SET_READ_LEN.NewValue(uint64(at.GetSize())))
	at.AddOp(OPC_SAVE_STRUCT)
	at.SetParseCB(SysinfoParse)
	return at
}

func StatfsParse(ctx IArgType, ptr uint64, buf *bytes.Buffer, parse_more bool) string {
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

func GetStatfs() IArgType {
	at := GetArgType("struct").Clone()
	at.CleanOpList()
	at.SetSize(uint32(unsafe.Sizeof(syscall.Statfs_t{})))
	at.AddOp(OPC_SET_READ_LEN.NewValue(uint64(at.GetSize())))
	at.AddOp(OPC_SAVE_STRUCT)
	at.SetParseCB(StatfsParse)
	return at
}

func EpollEventParse(ctx IArgType, ptr uint64, buf *bytes.Buffer, parse_more bool) string {
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

func GetEpollEvent() IArgType {
	at := GetArgType("struct").Clone()
	at.CleanOpList()
	at.SetSize(uint32(unsafe.Sizeof(syscall.EpollEvent{})))
	at.AddOp(OPC_SET_READ_LEN.NewValue(uint64(at.GetSize())))
	at.AddOp(OPC_SAVE_STRUCT)
	at.SetParseCB(EpollEventParse)
	return at
}
