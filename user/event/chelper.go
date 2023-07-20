package event

import "unsafe"

// #include <load_so.h>
// #cgo LDFLAGS: -ldl
import "C"

func ParseStack(pid uint32, buffer UnwindBuf) string {
	stack_str := C.get_stack(C.int(pid), C.ulong(((1 << 33) - 1)), unsafe.Pointer(&buffer))
	// char* 转到 go 的 string
	return C.GoString(stack_str)
}
