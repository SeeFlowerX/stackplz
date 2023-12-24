package next

import (
	"bytes"
	"fmt"
	"unsafe"
)

type ARG_NUM struct {
	ArgType
}

func (this *ARG_NUM) Setup() {

}

func (this *ARG_NUM) Parse(ptr uint64, buf *bytes.Buffer) string {
	return fmt.Sprintf("0x%x", ptr)
}

type ARG_PTR struct {
	ARG_NUM
}

type ARG_INT struct {
	ARG_NUM
}

type ARG_UINT struct {
	ARG_NUM
}

type ARG_INT8 struct {
	ARG_NUM
}

type ARG_INT16 struct {
	ARG_NUM
}

type ARG_INT32 struct {
	ARG_NUM
}

type ARG_INT64 struct {
	ARG_NUM
}

type ARG_UINT8 struct {
	ARG_NUM
}

type ARG_UINT16 struct {
	ARG_NUM
}

type ARG_UINT32 struct {
	ARG_NUM
}

type ARG_UINT64 struct {
	ARG_NUM
}

func (this *ARG_INT) Parse(ptr uint64, buf *bytes.Buffer) string {
	return fmt.Sprintf("%d", int32(ptr))
}
func (this *ARG_UINT) Parse(ptr uint64, buf *bytes.Buffer) string {
	return fmt.Sprintf("%d", uint32(ptr))
}
func (this *ARG_INT8) Parse(ptr uint64, buf *bytes.Buffer) string {
	return fmt.Sprintf("%d", int8(ptr))
}
func (this *ARG_INT16) Parse(ptr uint64, buf *bytes.Buffer) string {
	return fmt.Sprintf("%d", int16(ptr))
}
func (this *ARG_INT32) Parse(ptr uint64, buf *bytes.Buffer) string {
	return fmt.Sprintf("%d", int32(ptr))
}
func (this *ARG_INT64) Parse(ptr uint64, buf *bytes.Buffer) string {
	return fmt.Sprintf("%d", int64(ptr))
}
func (this *ARG_UINT8) Parse(ptr uint64, buf *bytes.Buffer) string {
	return fmt.Sprintf("%d", uint8(ptr))
}
func (this *ARG_UINT16) Parse(ptr uint64, buf *bytes.Buffer) string {
	return fmt.Sprintf("%d", uint16(ptr))
}
func (this *ARG_UINT32) Parse(ptr uint64, buf *bytes.Buffer) string {
	return fmt.Sprintf("%d", uint32(ptr))
}
func (this *ARG_UINT64) Parse(ptr uint64, buf *bytes.Buffer) string {
	return fmt.Sprintf("%d", uint64(ptr))
}

func init() {
	Register(&ARG_PTR{}, "ptr", TYPE_POINTER, uint32(unsafe.Sizeof(uint64(0))))
	Register(&ARG_INT{}, "int", TYPE_INT, uint32(unsafe.Sizeof(int32(0))))
	Register(&ARG_UINT{}, "uint", TYPE_UINT, uint32(unsafe.Sizeof(uint32(0))))
	Register(&ARG_INT8{}, "int8", TYPE_INT8, uint32(unsafe.Sizeof(int8(0))))
	Register(&ARG_INT16{}, "int16", TYPE_INT16, uint32(unsafe.Sizeof(int16(0))))
	Register(&ARG_INT32{}, "int32", TYPE_INT32, uint32(unsafe.Sizeof(int32(0))))
	Register(&ARG_INT64{}, "int64", TYPE_INT64, uint32(unsafe.Sizeof(int64(0))))
	Register(&ARG_UINT8{}, "uint8", TYPE_UINT8, uint32(unsafe.Sizeof(uint8(0))))
	Register(&ARG_UINT16{}, "uint16", TYPE_UINT16, uint32(unsafe.Sizeof(uint16(0))))
	Register(&ARG_UINT32{}, "uint32", TYPE_UINT32, uint32(unsafe.Sizeof(uint32(0))))
	Register(&ARG_UINT64{}, "uint64", TYPE_UINT64, uint32(unsafe.Sizeof(uint64(0))))
}
