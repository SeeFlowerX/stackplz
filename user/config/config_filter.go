package config

import "fmt"

type ConfigMap struct {
	stackplz_pid uint32
}

type CommonFilter struct {
	is_32bit        uint32
	trace_mode      uint32
	trace_uid_group uint32
	signal          uint32
}

type ThreadFilter struct {
	ThreadName [16]byte
}

const (
	UNKNOWN_FILTER uint32 = iota
	EQUAL_FILTER
	GREATER_FILTER
	LESS_FILTER
	WHITELIST_FILTER
	BLACKLIST_FILTER
	REPLACE_FILTER
)

type ArgFilter struct {
	Filter_type  uint32
	Filter_index uint32
	Num_val      uint64
	OldStr_val   [256]byte
	OldStr_len   uint32
	NewStr_val   [256]byte
	NewStr_len   uint32
}

func (this *ArgFilter) Match(name string) bool {
	if this.Filter_index == 0 {
		return false
	}
	return name == fmt.Sprintf("f%d", this.Filter_index-1)
}
