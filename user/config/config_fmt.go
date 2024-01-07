package config

import (
	"encoding/json"
	"fmt"
	"stackplz/user/util"
)

// BPF_ 与c的结构体一一对应
type ContextFields struct {
	Ts      uint64   `json:"ts"`
	EventId uint32   `json:"event_id"`
	HostTid uint32   `json:"host_tid"`
	HostPid uint32   `json:"host_pid"`
	Tid     uint32   `json:"tid"`
	Pid     uint32   `json:"pid"`
	Uid     uint32   `json:"uid"`
	Comm    [16]byte `json:"comm"`
	Argnum  uint8    `json:"arg_num"`
	Padding [7]byte  `json:"-"`
}

func (this *ContextFields) MarshalJSON() ([]byte, error) {
	type Alias ContextFields
	return json.Marshal(&struct {
		Comm string `json:"comm"`
		*Alias
	}{
		Comm:  util.B2STrim(this.Comm[:]),
		Alias: (*Alias)(this),
	})
}

type SyscallFields struct {
	NR         uint32 `json:"nr"`
	LR         uint64 `json:"-"`
	SP         uint64 `json:"-"`
	PC         uint64 `json:"-"`
	PointName  string `json:"point_name"`
	PointStr   string `json:"point_str"`
	PointValue any    `json:"point_value"`
}

type UprobeFields struct {
	ProbeIndex uint32 `json:"probe_index"`
	LR         uint64 `json:"lr"`
	SP         uint64 `json:"sp"`
	PC         uint64 `json:"pc"`
	ArgName    string `json:"arg_name"`
	ArgStr     string `json:"arg_str"`
}

type Mmap2Fields struct {
	Pid            uint32 `json:"pid"`
	Tid            uint32 `json:"tid"`
	Addr           uint64 `json:"addr"`
	Len            uint64 `json:"len"`
	Pgoff          uint64 `json:"pgoff"`
	Maj            uint32 `json:"maj"`
	Min            uint32 `json:"min"`
	Ino            uint64 `json:"ino"`
	Ino_generation uint64 `json:"ino_generation"`
	Prot           uint32 `json:"prot"`
	Flags          uint32 `json:"flags"`
	Filename       string `json:"filename"`
	Sample_id      []byte `json:"-"`
}

func (this *Mmap2Fields) MarshalJSON() ([]byte, error) {
	type Alias Mmap2Fields
	return json.Marshal(&struct {
		Event string `json:"event"`
		Addr  string `json:"addr"`
		Len   string `json:"len"`
		Pgoff string `json:"pgoff"`
		Prot  string `json:"prot"`
		Flags string `json:"flags"`
		*Alias
	}{
		Event: "mmap2",
		Addr:  fmt.Sprintf("0x%x", this.Addr),
		Len:   fmt.Sprintf("0x%x", this.Len),
		Pgoff: fmt.Sprintf("0x%x", this.Pgoff),
		Prot:  fmt.Sprintf("0x%x", this.Prot),
		Flags: fmt.Sprintf("0x%x", this.Flags),
		Alias: (*Alias)(this),
	})
}

type ForkFields struct {
	Pid       uint32 `json:"pid"`
	Ppid      uint32 `json:"ppid"`
	Tid       uint32 `json:"tid"`
	Ptid      uint32 `json:"ptid"`
	Time      uint64 `json:"time"`
	Sample_id []byte `json:"-"`
}

func (this *ForkFields) MarshalJSON() ([]byte, error) {
	type Alias ForkFields
	return json.Marshal(&struct {
		Event string `json:"event"`
		*Alias
	}{
		Event: "fork",
		Alias: (*Alias)(this),
	})
}

// 这俩一样的
type ExitFields struct {
	ForkFields
}

func (this *ExitFields) MarshalJSON() ([]byte, error) {
	type Alias ExitFields
	return json.Marshal(&struct {
		Event string `json:"event"`
		*Alias
	}{
		Event: "exit",
		Alias: (*Alias)(this),
	})
}

type CommFields struct {
	Pid       uint32 `json:"pid"`
	Tid       uint32 `json:"tid"`
	Comm      string `json:"comm"`
	Sample_id []byte `json:"-"`
}

func (this *CommFields) MarshalJSON() ([]byte, error) {
	type Alias CommFields
	return json.Marshal(&struct {
		Event string `json:"event"`
		*Alias
	}{
		Event: "comm",
		Alias: (*Alias)(this),
	})
}
