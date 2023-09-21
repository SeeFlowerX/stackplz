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

type BPF_record_mmap2 struct {
	Pid            uint32
	Tid            uint32
	Addr           uint64
	Len            uint64
	Pgoff          uint64
	Maj            uint32
	Min            uint32
	Ino            uint64
	Ino_generation uint64
	Prot           uint32
	Flags          uint32
	Filename       string
	Sample_id      []byte
}

type FMT_record_mmap2 struct {
	Event          string `json:"event"`
	Pid            uint32 `json:"pid"`
	Tid            uint32 `json:"tid"`
	Addr           string `json:"addr"`
	Len            string `json:"len"`
	Pgoff          string `json:"pgoff"`
	Maj            uint32 `json:"maj"`
	Min            uint32 `json:"min"`
	Ino            uint64 `json:"ino"`
	Ino_generation uint64 `json:"ino_generation"`
	Prot           string `json:"prot"`
	Flags          string `json:"flags"`
	Filename       string `json:"filename"`
}

type BPF_record_fork struct {
	Pid       uint32
	Ppid      uint32
	Tid       uint32
	Ptid      uint32
	Time      uint64
	Sample_id []byte
}

type FMT_record_fork struct {
	Event string `json:"event"`
	Pid   uint32 `json:"pid"`
	Ppid  uint32 `json:"ppid"`
	Tid   uint32 `json:"tid"`
	Ptid  uint32 `json:"ptid"`
	Time  uint64 `json:"time"`
}

type BPF_record_exit struct {
	Pid       uint32
	Ppid      uint32
	Tid       uint32
	Ptid      uint32
	Time      uint64
	Sample_id []byte
}

type FMT_record_exit struct {
	Event string `json:"event"`
	Pid   uint32 `json:"pid"`
	Ppid  uint32 `json:"ppid"`
	Tid   uint32 `json:"tid"`
	Ptid  uint32 `json:"ptid"`
	Time  uint64 `json:"time"`
}

type BPF_record_comm struct {
	Pid       uint32
	Tid       uint32
	Comm      string
	Sample_id []byte
}

type FMT_record_comm struct {
	Event string `json:"event"`
	Pid   uint32 `json:"pid"`
	Tid   uint32 `json:"tid"`
	Comm  string `json:"comm"`
}
