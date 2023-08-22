package config

const MAX_COUNT = 20
const MAX_WATCH_PROC_COUNT = 256

// stackplz => 737461636b706c7a
const MAGIC_UID = 0x73746163
const MAGIC_PID = 0x6b706c7a
const MAGIC_TID = 0x61636b70

const (
	TRACE_COMMON uint32 = iota
	TRACE_ALL
	TRACE_FILE
	TRACE_PROCESS
	TRACE_NET
	TRACE_SIGNAL
	TRACE_STAT
)

const MAX_BUF_READ_SIZE uint32 = 4096

const (
	REG_ARM64_X0 uint32 = iota
	REG_ARM64_X1
	REG_ARM64_X2
	REG_ARM64_X3
	REG_ARM64_X4
	REG_ARM64_X5
	REG_ARM64_X6
	REG_ARM64_X7
	REG_ARM64_X8
	REG_ARM64_X9
	REG_ARM64_X10
	REG_ARM64_X11
	REG_ARM64_X12
	REG_ARM64_X13
	REG_ARM64_X14
	REG_ARM64_X15
	REG_ARM64_X16
	REG_ARM64_X17
	REG_ARM64_X18
	REG_ARM64_X19
	REG_ARM64_X20
	REG_ARM64_X21
	REG_ARM64_X22
	REG_ARM64_X23
	REG_ARM64_X24
	REG_ARM64_X25
	REG_ARM64_X26
	REG_ARM64_X27
	REG_ARM64_X28
	REG_ARM64_X29
	REG_ARM64_LR
	REG_ARM64_SP
	REG_ARM64_PC
	REG_ARM64_MAX
)

var ProtFlags map[string]int32 = map[string]int32{
	"PROT_READ":  int32(0x1),
	"PROT_WRITE": int32(0x2),
	"PROT_EXEC":  int32(0x4),
	"PROT_SEM":   int32(0x8),
	// "PROT_NONE":      int32(0x0),
	"PROT_GROWSDOWN": int32(0x01000000),
	"PROT_GROWSUP":   int32(0x02000000),
}

var FileFlags map[string]int32 = map[string]int32{
	// https://cs.android.com/android/kernel/superproject/+/common-android-mainline:common/include/uapi/asm-generic/fcntl.h
	"O_ACCMODE": int32(00000003),
	// "O_RDONLY":   int32(00000000),
	"O_WRONLY":   int32(00000001),
	"O_RDWR":     int32(00000002),
	"O_CREAT":    int32(00000100),
	"O_EXCL":     int32(00000200),
	"O_NOCTTY":   int32(00000400),
	"O_TRUNC":    int32(00001000),
	"O_APPEND":   int32(00002000),
	"O_NONBLOCK": int32(00004000),
	"O_DSYNC":    int32(00010000),
	"FASYNC":     int32(00020000),
	// "O_DIRECT":    int32(00040000),
	// "O_LARGEFILE": int32(00100000),
	// "O_DIRECTORY": int32(00200000),
	// "O_NOFOLLOW":  int32(00400000),
	"O_NOATIME": int32(01000000),
	"O_CLOEXEC": int32(02000000),
	// 注意不同架构的 flag 定义不一样
	// https://cs.android.com/android/kernel/superproject/+/common-android-mainline:common/arch/arm64/include/uapi/asm/fcntl.h
	"O_DIRECTORY": int32(00040000),
	"O_NOFOLLOW":  int32(00100000),
	"O_DIRECT":    int32(00200000),
	"O_LARGEFILE": int32(00400000),
}

var MapFlags map[string]int32 = map[string]int32{
	"MAP_SHARED":          int32(0x01),
	"MAP_PRIVATE":         int32(0x02),
	"MAP_SHARED_VALIDATE": int32(0x03),
	"MAP_TYPE":            int32(0x0f),
	"MAP_FIXED":           int32(0x10),
	"MAP_ANONYMOUS":       int32(0x20),
	"MAP_POPULATE":        int32(0x008000),
	"MAP_NONBLOCK":        int32(0x010000),
	"MAP_STACK":           int32(0x020000),
	"MAP_HUGETLB":         int32(0x040000),
	"MAP_SYNC":            int32(0x080000),
	"MAP_FIXED_NOREPLACE": int32(0x100000),
	"MAP_UNINITIALIZED":   int32(0x4000000),
}

var MreapFlags map[string]int32 = map[string]int32{
	"MREMAP_MAYMOVE":   1,
	"MREMAP_FIXED":     2,
	"MREMAP_DONTUNMAP": 4,
}
