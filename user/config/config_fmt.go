package config

// BPF_ 与c的结构体一一对应
type BPF_event_context struct {
	Ts      uint64
	EventId uint32
	HostTid uint32
	HostPid uint32
	Tid     uint32
	Pid     uint32
	Uid     uint32
	Comm    [16]byte
	Argnum  uint8
	Padding [7]byte
}

type FMT_event_context struct {
	Ts      uint64 `json:"ts"`
	Event   string `json:"event"`
	HostTid uint32 `json:"host_tid"`
	HostPid uint32 `json:"host_pid"`
	Tid     uint32 `json:"tid"`
	Pid     uint32 `json:"pid"`
	Uid     uint32 `json:"uid"`
	Comm    string `json:"comm"`
	Argnum  uint8  `json:"arg_num"`
}

type UprobeFmt struct {
	FMT_event_context
	Stack   string `json:"stack"`
	LR      string `json:"lr"`
	SP      string `json:"sp"`
	PC      string `json:"pc"`
	Arg_str string `json:"arg_str"`
}

type SyscallFmt struct {
	FMT_event_context
	Stack   string `json:"stack"`
	NR      string `json:"nr"`
	LR      string `json:"lr"`
	SP      string `json:"sp"`
	PC      string `json:"pc"`
	Arg_str string `json:"arg_str"`
}

type SyscallExitFmt struct {
	FMT_event_context
	Stack   string `json:"stack"`
	NR      string `json:"nr"`
	Ret     uint64 `json:"ret"`
	Arg_str string `json:"arg_str"`
}
