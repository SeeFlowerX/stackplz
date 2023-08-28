package config

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
	WHITELIST_FILTER
	BLACKLIST_FILTER
	REPLACE_FILTER
)

type ArgFilter struct {
	Filter_type  uint32
	Helper_index uint32
	Num_val      uint64
	Str_val      [256]byte
}

type ArgReplaceFilter struct {
	Old_str_val [256]byte
	New_str_val [256]byte
}
