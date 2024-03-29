package event

import (
	"os"
	"path"
	"unsafe"
)

// #include <load_so.h>
// #cgo LDFLAGS: -ldl
import "C"

var LibPath string

func ParseStack(map_buffer string, opt *UnwindOption, ubuf *UnwindBuf) string {
	stack_str := C.get_stack(C.CString(LibPath), C.CString(map_buffer), unsafe.Pointer(opt), unsafe.Pointer(&ubuf.Regs[0]), unsafe.Pointer(&ubuf.Data[0]))
	// char* 转到 go 的 string
	return C.GoString(stack_str)
}

func ParseStackV2(pid uint32, opt *UnwindOption, ubuf *UnwindBuf) string {
	stack_str := C.get_stackv2(C.CString(LibPath), C.int(pid), unsafe.Pointer(opt), unsafe.Pointer(&ubuf.Regs[0]), unsafe.Pointer(&ubuf.Data[0]))
	// char* 转到 go 的 string
	return C.GoString(stack_str)
}

func init() {
	exec_path, err := os.Executable()
	if err != nil {
		return
	}
	// 获取一次 后面用得到 免去重复获取
	exec_path = path.Dir(exec_path)
	LibPath = exec_path + "/" + "preload_libs"
}
