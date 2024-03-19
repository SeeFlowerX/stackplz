package util

type Utsname struct {
	Sysname    [65]int8
	Nodename   [65]int8
	Release    [65]int8
	Version    [65]int8
	Machine    [65]int8
	Domainname [65]int8
}

type Timespec struct {
	Sec  int64
	Nsec int64
}

type UtsnameArm struct {
	Sysname    [65]uint8
	Nodename   [65]uint8
	Release    [65]uint8
	Version    [65]uint8
	Machine    [65]uint8
	Domainname [65]uint8
}

type TimespecArm struct {
	Sec  int32
	Nsec int32
}
