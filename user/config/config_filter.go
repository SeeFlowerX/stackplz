package config

type ConfigMap struct {
	filter_mode  uint32
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

type RevFilter struct {
	RevString [32]byte
}
