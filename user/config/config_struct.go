package config

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"stackplz/user/util"
	"strings"
	"syscall"
	"unsafe"
)

type Sigaction struct {
	Sa_handler   uint64
	Sa_sigaction uint64
	Sa_mask      uint64
	Sa_flags     uint64
	Sa_restorer  uint64
}

type Pollfd struct {
	Fd      int32
	Events  uint16
	Revents uint16
}

// https://cs.android.com/android/kernel/superproject/+/common-android-mainline:common/include/uapi/asm-generic/siginfo.h
type SigInfo struct {
	Si_signo int32
	Si_errno int32
	Si_code  int32
	// 解决对齐的问题...
	_ int32
	// 这是个union字段 类型根据具体的signal决定
	Sifields uint64
}
type Msghdr struct {
	Name       uint64
	Namelen    uint32
	Pad_cgo_0  [4]byte
	Iov        uint64
	Iovlen     uint64
	Control    uint64
	Controllen uint64
	Flags      int32
	Pad_cgo_1  [4]byte
}
type ItTmerspec struct {
	It_interval syscall.Timespec
	It_value    syscall.Timespec
}
type Stack_t struct {
	Ss_sp    uint64
	Ss_flags int32
	Ss_size  int32
}
type TimeZone_t struct {
	Tz_minuteswest int32
	Tz_dsttime     int32
}

// GO 中结构体这个 padding 用 unsafe.Sizeof 会直接给你算上
// 用 binary.Size 则直接就是对应的大小
// 如果用 unsafe.Sizeof 这个大小去解析对应的二进制
// 那么如果原本结构体里面没有设置好 padding 那么解析就有问题
// 稳妥做法就是自己 补全存在 padding 的位置 注意位置不一定是结尾
// 选 binary.Size 可以省事儿一点 潜在的问题暂时不清楚 不同类型混搭用这个有些奇怪的问题 和对齐有关

type Pthread_attr_t struct {
	Flags          uint32
	_              uint32
	Stack_base     uint64
	Stack_size     int64
	Guard_size     int64
	Sched_policy   int32
	Sched_priority int32
	// // 这个字段是 64 位才有的 暂时忽略吧...
	// Reserved       [16]byte
}

func (this *Pthread_attr_t) Format() string {
	var fields []string
	// fields = append(fields, fmt.Sprintf("[debug index:%d len:%d]", this.Index, this.Len))
	fields = append(fields, fmt.Sprintf("flags=0x%x", this.Flags))
	fields = append(fields, fmt.Sprintf("stack_base=0x%x", this.Stack_base))
	fields = append(fields, fmt.Sprintf("stack_size=0x%x", this.Stack_size))
	fields = append(fields, fmt.Sprintf("guard_size=0x%x", this.Guard_size))
	fields = append(fields, fmt.Sprintf("sched_policy=0x%x", this.Sched_policy))
	fields = append(fields, fmt.Sprintf("sched_priority=0x%x", this.Sched_priority))
	return fmt.Sprintf("{%s}", strings.Join(fields, ", "))
}

type ArgFormatter interface {
	Format() string
}

type ArgHexFormatter interface {
	HexFormat() string
}

type Arg_nr struct {
	Index uint8
	Value uint32
}

func (this *Arg_nr) Format() string {
	var fields []string
	fields = append(fields, fmt.Sprintf("[debug index:%d nr:%d]", this.Index, this.Value))
	return fmt.Sprintf("{%s}", strings.Join(fields, ", "))
}

type Arg_iovcnt struct {
	Index uint8
	Value uint32
}
type Arg_probe_index struct {
	Index uint8
	Value uint32
}
type Arg_reg struct {
	Index   uint8
	Address uint64
}

func (this *Arg_reg) Format() string {
	var fields []string
	fields = append(fields, fmt.Sprintf("[debug index:%d address:0x%x]", this.Index, this.Address))
	return fmt.Sprintf("{%s}", strings.Join(fields, ", "))
}

type Arg_str struct {
	Index uint8
	Len   uint32
}

func (this *Arg_str) Format(payload []byte) string {
	// hexdump := util.HexDumpPure(payload)
	hexdump := util.PrettyByteSlice(payload)
	return fmt.Sprintf("(%s)", hexdump)
}

func (this *Arg_str) HexFormat(payload []byte, color bool) string {
	var hexdump string
	if color {
		hexdump = util.HexDumpGreen(payload)
	} else {
		hexdump = util.HexDumpPure(payload)
	}
	return fmt.Sprintf("(\n%s)", hexdump)
}

type Arg_str_arr struct {
	Index uint8
	Count uint8
}

type Arg_Timespec struct {
	Index uint8
	Len   uint32
	syscall.Timespec
}

func (this *Arg_Timespec) Format() string {
	var fields []string
	fields = append(fields, fmt.Sprintf("sec=%d", this.Sec))
	fields = append(fields, fmt.Sprintf("nsec=%d", this.Nsec))
	return fmt.Sprintf("{%s}", strings.Join(fields, ", "))
}

type Arg_TimeZone_t struct {
	Index uint8
	Len   uint32
	TimeZone_t
}

func (this *Arg_TimeZone_t) Format() string {
	var fields []string
	fields = append(fields, fmt.Sprintf("tz_minuteswest=%d", this.Tz_minuteswest))
	fields = append(fields, fmt.Sprintf("tz_dsttime=%d", this.Tz_dsttime))
	return fmt.Sprintf("{%s}", strings.Join(fields, ", "))
}

type Arg_Pthread_attr_t struct {
	Index uint8
	Len   uint32
	Pthread_attr_t
}

func (this *Arg_Pthread_attr_t) Format() string {
	var fields []string
	fields = append(fields, fmt.Sprintf("Flags=0x%x", this.Flags))
	fields = append(fields, fmt.Sprintf("Stack_base=0x%x", this.Stack_base))
	fields = append(fields, fmt.Sprintf("Stack_size=0x%x", this.Stack_size))
	fields = append(fields, fmt.Sprintf("Guard_size=0x%x", this.Guard_size))
	fields = append(fields, fmt.Sprintf("Sched_policy=0x%x", this.Sched_policy))
	fields = append(fields, fmt.Sprintf("Sched_priority=0x%x", this.Sched_priority))
	return fmt.Sprintf("{%s}", strings.Join(fields, ", "))
}

type Arg_Timeval struct {
	Index uint8
	Len   uint32
	syscall.Timeval
}

func (this *Arg_Timeval) Format() string {
	var fields []string
	fields = append(fields, fmt.Sprintf("sec=%d", this.Sec))
	fields = append(fields, fmt.Sprintf("usec=%d", this.Usec))
	return fmt.Sprintf("{%s}", strings.Join(fields, ", "))
}

type Arg_Sigaction struct {
	Index uint8
	Len   uint32
	Sigaction
}

func (this *Arg_Sigaction) Format() string {
	var fields []string
	fields = append(fields, fmt.Sprintf("sa_handler=0x%x", this.Sa_handler))
	fields = append(fields, fmt.Sprintf("sa_sigaction=0x%x", this.Sa_sigaction))
	fields = append(fields, fmt.Sprintf("sa_mask=0x%x", this.Sa_mask))
	fields = append(fields, fmt.Sprintf("sa_flags=0x%x", this.Sa_flags))
	fields = append(fields, fmt.Sprintf("sa_restorer=0x%x", this.Sa_restorer))
	return fmt.Sprintf("{%s}", strings.Join(fields, ", "))
}

type Arg_Pollfd struct {
	Index uint8
	Len   uint32
	Pollfd
}

func (this *Arg_Pollfd) Format() string {
	return fmt.Sprintf("{fd=%d, events=%d, revents=%d}", this.Fd, this.Events, this.Revents)
}

type Arg_Stat_t struct {
	Index uint8
	Len   uint32
	syscall.Stat_t
}

// vscode 配置下面的部分 这样才有正确的代码提示
// "go.toolsEnvVars": {
//     "GOOS": "android",
//     "GOARCH": "arm64"
// }

func (this *Arg_Stat_t) Format() string {
	var fields []string
	fields = append(fields, fmt.Sprintf("dev=%d", this.Dev))
	fields = append(fields, fmt.Sprintf("ino=%d", this.Ino))
	fields = append(fields, fmt.Sprintf("nlink=%d", this.Nlink))
	fields = append(fields, fmt.Sprintf("mode=%d", this.Mode))
	fields = append(fields, fmt.Sprintf("uid=%d", this.Uid))
	fields = append(fields, fmt.Sprintf("gid=%d", this.Gid))
	fields = append(fields, fmt.Sprintf("rdev=%d", this.Rdev))
	fields = append(fields, fmt.Sprintf("x__pad1=%d", this.X__pad1))
	fields = append(fields, fmt.Sprintf("size=%d", this.Size))
	fields = append(fields, fmt.Sprintf("blksize=%d", this.Blksize))
	fields = append(fields, fmt.Sprintf("x__pad2=%d", this.X__pad2))
	fields = append(fields, fmt.Sprintf("blocks=%d", this.Blocks))
	fields = append(fields, fmt.Sprintf("atim={tv_sec=%d, tv_nsec=%d}", this.Atim.Sec, this.Atim.Nsec))
	fields = append(fields, fmt.Sprintf("mtim={tv_sec=%d, tv_nsec=%d}", this.Mtim.Sec, this.Mtim.Nsec))
	fields = append(fields, fmt.Sprintf("ctim={tv_sec=%d, tv_nsec=%d}", this.Ctim.Sec, this.Ctim.Nsec))
	fields = append(fields, fmt.Sprintf("x__glibc_reserved=0x%x,0x%x", this.X__glibc_reserved[0], this.X__glibc_reserved[1]))
	return fmt.Sprintf("{%s}", strings.Join(fields, ", "))
}

type Arg_Statfs_t struct {
	Index uint8
	Len   uint32
	syscall.Statfs_t
}

func (this *Arg_Statfs_t) Format() string {
	var fields []string
	fields = append(fields, fmt.Sprintf("type=%d", this.Type))
	fields = append(fields, fmt.Sprintf("bsize=%d", this.Bsize))
	fields = append(fields, fmt.Sprintf("blocks=%d", this.Blocks))
	fields = append(fields, fmt.Sprintf("bfree=%d", this.Bfree))
	fields = append(fields, fmt.Sprintf("bavail=%d", this.Bavail))
	fields = append(fields, fmt.Sprintf("files=%d", this.Files))
	fields = append(fields, fmt.Sprintf("ffree=%d", this.Ffree))
	fields = append(fields, fmt.Sprintf("fsid=0x%x,0x%x", this.Fsid.X__val[0], this.Fsid.X__val[1]))
	fields = append(fields, fmt.Sprintf("namelen=%d", this.Namelen))
	fields = append(fields, fmt.Sprintf("frsize=%d", this.Frsize))
	fields = append(fields, fmt.Sprintf("flags=%d", this.Flags))
	fields = append(fields, fmt.Sprintf("spare=0x%x,0x%x,0x%x,0x%x", this.Spare[0], this.Spare[1], this.Spare[2], this.Spare[3]))
	return fmt.Sprintf("{%s}", strings.Join(fields, ", "))
}

type Arg_Utsname struct {
	Index uint8
	Len   uint32
	syscall.Utsname
}

func (this *Arg_Utsname) Format() string {
	var fields []string
	fields = append(fields, fmt.Sprintf("sysname=%s", util.B2S(this.Sysname[:])))
	fields = append(fields, fmt.Sprintf("nodename=%s", util.B2S(this.Nodename[:])))
	fields = append(fields, fmt.Sprintf("release=%s", util.B2S(this.Release[:])))
	fields = append(fields, fmt.Sprintf("version=%s", util.B2S(this.Version[:])))
	fields = append(fields, fmt.Sprintf("machine=%s", util.B2S(this.Machine[:])))
	fields = append(fields, fmt.Sprintf("domainname=%s", util.B2S(this.Domainname[:])))
	return fmt.Sprintf("{%s}", strings.Join(fields, ", "))
}

type Arg_RawSockaddrUnix struct {
	Index uint8
	Len   uint32
	syscall.RawSockaddrUnix
}

func (this *Arg_RawSockaddrUnix) Format() string {
	var fields []string
	if this.Family == syscall.AF_FILE {
		fields = append(fields, "family=AF_FILE")
		fields = append(fields, fmt.Sprintf("path=%s", util.B2S(this.Path[:])))
	} else if this.Family == syscall.AF_INET {
		fields = append(fields, "family=AF_INET")
		sockaddr := (*syscall.RawSockaddrInet4)(unsafe.Pointer(&this.RawSockaddrUnix))
		fields = append(fields, fmt.Sprintf("port=%d", sockaddr.Port))
		fields = append(fields, fmt.Sprintf("addr=%s", net.IP(sockaddr.Addr[:]).String()))
		fields = append(fields, fmt.Sprintf("zero=%x", sockaddr.Zero))
	} else if this.Family == syscall.AF_INET6 {
		fields = append(fields, "family=AF_INET6")
		buf := &bytes.Buffer{}
		err := binary.Write(buf, binary.BigEndian, this.RawSockaddrUnix)
		if err != nil {
			panic(err)
		}
		var sockaddr6 syscall.RawSockaddrInet6
		err = binary.Read(buf, binary.LittleEndian, &sockaddr6.Family)
		if err != nil {
			panic(err)
		}
		err = binary.Read(buf, binary.BigEndian, &sockaddr6.Port)
		if err != nil {
			panic(err)
		}
		err = binary.Read(buf, binary.BigEndian, &sockaddr6.Flowinfo)
		if err != nil {
			panic(err)
		}
		err = binary.Read(buf, binary.LittleEndian, &sockaddr6.Addr)
		if err != nil {
			panic(err)
		}
		err = binary.Read(buf, binary.LittleEndian, &sockaddr6.Scope_id)
		if err != nil {
			panic(err)
		}
		fields = append(fields, fmt.Sprintf("port=%d", sockaddr6.Port))
		fields = append(fields, fmt.Sprintf("flowinfo=%d", sockaddr6.Flowinfo))
		// 好像还是会解析成ipv4
		fields = append(fields, fmt.Sprintf("addr=%s", net.IP(sockaddr6.Addr[:]).String()))
		fields = append(fields, fmt.Sprintf("scope_id=%d", sockaddr6.Scope_id))
	} else if this.Family == syscall.AF_UNSPEC {
		// 暂时不知道这个怎么解析比较好
		fields = append(fields, "family=AF_UNSPEC")
		fields = append(fields, fmt.Sprintf("path=\n%s", util.HexDump(util.I2B(this.Path[:]), util.COLORGREEN)))
	} else {
		fields = append(fields, fmt.Sprintf("family=0x%x", this.Family))
		fields = append(fields, fmt.Sprintf("path=\n%s", util.HexDump(util.I2B(this.Path[:]), util.COLORGREEN)))
	}
	return fmt.Sprintf("{%s}", strings.Join(fields, ", "))
}

type Arg_Iovec struct {
	Index  uint8
	Base   uint64
	BufLen uint64
}

type Arg_Iovec_Fix struct {
	Index  uint8
	Len    uint32
	Base   uint64
	BufLen uint64
}
type Arg_Iovec_Fix_t struct {
	Arg_Iovec_Fix
	Payload []byte
}

func (this *Arg_Iovec_Fix_t) Format() string {
	var fields []string
	// fields = append(fields, fmt.Sprintf("index=%d", this.Index))
	// fields = append(fields, fmt.Sprintf("len=%d", this.Len))
	fields = append(fields, fmt.Sprintf("base=0x%x(%s)", this.Base, util.PrettyByteSlice(this.Payload)))
	fields = append(fields, fmt.Sprintf("buflen=0x%x", this.BufLen))
	return fmt.Sprintf("(%s)", strings.Join(fields, ", "))
}

type Arg_Iovec_t struct {
	Arg_Iovec
	Payload []byte
}

func (this *Arg_Iovec_t) Format() string {
	var fields []string
	fields = append(fields, fmt.Sprintf("base=0x%x", this.Base))
	fields = append(fields, fmt.Sprintf("len=0x%x", this.BufLen))
	fields = append(fields, fmt.Sprintf("buf=(%s)", util.PrettyByteSlice(this.Payload)))
	return fmt.Sprintf("{%s}", strings.Join(fields, ", "))
}

type Arg_EpollEvent struct {
	Index uint8
	Len   uint32
	syscall.EpollEvent
}

func (this *Arg_EpollEvent) Format() string {
	var fields []string
	fields = append(fields, fmt.Sprintf("events=0x%x", this.Events))
	// fields = append(fields, fmt.Sprintf("_=*"))
	fields = append(fields, fmt.Sprintf("fd=%d", this.Fd))
	// fields = append(fields, fmt.Sprintf("pad=%d", this.Pad))
	return fmt.Sprintf("{%s}", strings.Join(fields, ", "))
}

type Arg_Rusage struct {
	Index uint8
	Len   uint32
	syscall.Rusage
}

func (this *Arg_Rusage) Format() string {
	var fields []string
	fields = append(fields, fmt.Sprintf("utime=timeval{sec=%d, usec=%d}", this.Utime.Sec, this.Utime.Usec))
	fields = append(fields, fmt.Sprintf("stime=timeval{sec=%d, usec=%d}", this.Stime.Sec, this.Stime.Usec))
	fields = append(fields, fmt.Sprintf("Maxrss=0x%x", this.Maxrss))
	fields = append(fields, fmt.Sprintf("Ixrss=0x%x", this.Ixrss))
	fields = append(fields, fmt.Sprintf("Idrss=0x%x", this.Idrss))
	fields = append(fields, fmt.Sprintf("Isrss=0x%x", this.Isrss))
	fields = append(fields, fmt.Sprintf("Minflt=0x%x", this.Minflt))
	fields = append(fields, fmt.Sprintf("Majflt=0x%x", this.Majflt))
	fields = append(fields, fmt.Sprintf("Nswap=0x%x", this.Nswap))
	fields = append(fields, fmt.Sprintf("Inblock=0x%x", this.Inblock))
	fields = append(fields, fmt.Sprintf("Oublock=0x%x", this.Oublock))
	fields = append(fields, fmt.Sprintf("Msgsnd=0x%x", this.Msgsnd))
	fields = append(fields, fmt.Sprintf("Msgrcv=0x%x", this.Msgrcv))
	fields = append(fields, fmt.Sprintf("Nsignals=0x%x", this.Nsignals))
	fields = append(fields, fmt.Sprintf("Nvcsw=0x%x", this.Nvcsw))
	fields = append(fields, fmt.Sprintf("Nivcsw=0x%x", this.Nivcsw))
	return fmt.Sprintf("{%s}", strings.Join(fields, ", "))
}

type Arg_Sysinfo_t struct {
	Index uint8
	Len   uint32
	syscall.Sysinfo_t
}

func (this *Arg_Sysinfo_t) Format() string {
	var fields []string
	fields = append(fields, fmt.Sprintf("uptime=0x%x", this.Uptime))
	fields = append(fields, fmt.Sprintf("loads=0x%x,0x%x,0x%x", this.Loads[0], this.Loads[1], this.Loads[2]))
	fields = append(fields, fmt.Sprintf("totalram=0x%x", this.Totalram))
	fields = append(fields, fmt.Sprintf("freeram=0x%x", this.Freeram))
	fields = append(fields, fmt.Sprintf("sharedram=0x%x", this.Sharedram))
	fields = append(fields, fmt.Sprintf("bufferram=0x%x", this.Bufferram))
	fields = append(fields, fmt.Sprintf("totalswap=0x%x", this.Totalswap))
	fields = append(fields, fmt.Sprintf("freeswap=0x%x", this.Freeswap))
	fields = append(fields, fmt.Sprintf("procs=0x%x", this.Procs))
	fields = append(fields, fmt.Sprintf("pad=0x%x", this.Pad))
	fields = append(fields, fmt.Sprintf("totalhigh=0x%x", this.Totalhigh))
	fields = append(fields, fmt.Sprintf("freehigh=0x%x", this.Freehigh))
	fields = append(fields, fmt.Sprintf("unit=0x%x", this.Unit))
	return fmt.Sprintf("{%s}", strings.Join(fields, ", "))
}

type Arg_SigInfo struct {
	Index uint8
	Len   uint32
	SigInfo
}

func (this *Arg_SigInfo) Format() string {
	var fields []string
	fields = append(fields, fmt.Sprintf("si_signo=0x%x", this.Si_signo))
	fields = append(fields, fmt.Sprintf("si_errno=0x%x", this.Si_errno))
	fields = append(fields, fmt.Sprintf("si_code=0x%x", this.Si_code))
	fields = append(fields, fmt.Sprintf("sifields=0x%x", this.Sifields))
	return fmt.Sprintf("{%s}", strings.Join(fields, ", "))
}

type Arg_Msghdr struct {
	Index uint8
	Len   uint32
	Msghdr
}

func (this *Arg_Msghdr) Format() string {
	var fields []string
	fields = append(fields, fmt.Sprintf("name=0x%x", this.Name))
	fields = append(fields, fmt.Sprintf("namelen=0x%x", this.Namelen))
	fields = append(fields, fmt.Sprintf("*iov=0x%x", this.Iov))
	fields = append(fields, fmt.Sprintf("iovlen=0x%x", this.Iovlen))
	fields = append(fields, fmt.Sprintf("*control=0x%x", this.Control))
	fields = append(fields, fmt.Sprintf("controllen=0x%x", this.Controllen))
	fields = append(fields, fmt.Sprintf("flags=0x%x", this.Flags))
	return fmt.Sprintf("(%s)", strings.Join(fields, ", "))
}

func (this *Arg_Msghdr) FormatFull(iov_fmt, control_fmt string) string {
	var fields []string
	fields = append(fields, fmt.Sprintf("name=0x%x", this.Name))
	fields = append(fields, fmt.Sprintf("namelen=0x%x", this.Namelen))
	fields = append(fields, fmt.Sprintf("*iov=0x%x%s", this.Iov, iov_fmt))
	fields = append(fields, fmt.Sprintf("iovlen=0x%x", this.Iovlen))
	fields = append(fields, fmt.Sprintf("*control=0x%x%s", this.Control, control_fmt))
	fields = append(fields, fmt.Sprintf("controllen=0x%x", this.Controllen))
	fields = append(fields, fmt.Sprintf("flags=0x%x", this.Flags))
	return fmt.Sprintf("(%s)", strings.Join(fields, ", "))
}

type Arg_ItTmerspec struct {
	Index uint8
	Len   uint32
	ItTmerspec
}

func (this *Arg_ItTmerspec) Format() string {
	var fields []string
	fields = append(fields, fmt.Sprintf("it_interval={sec=%d, nsec=%d}", this.It_interval.Sec, this.It_interval.Nsec))
	fields = append(fields, fmt.Sprintf("it_value={sec=%d, nsec=%d}", this.It_value.Sec, this.It_value.Nsec))
	return fmt.Sprintf("{%s}", strings.Join(fields, ", "))
}

type Arg_Stack_t struct {
	Index uint8
	Len   uint32
	Stack_t
}

func (this *Arg_Stack_t) Format() string {
	var fields []string
	fields = append(fields, fmt.Sprintf("ss_sp=0x%x", this.Ss_sp))
	fields = append(fields, fmt.Sprintf("ss_flags=%d", this.Ss_flags))
	fields = append(fields, fmt.Sprintf("ss_size=%d", this.Ss_size))
	return fmt.Sprintf("{%s}", strings.Join(fields, ", "))
}
