package config

type UprobeArgs struct {
	LibPath string
	PointArgs
}
type UArgs = UprobeArgs

func init() {

	libc_path := "/apex/com.android.runtime/lib64/bionic/libc.so"

	Register(&UArgs{libc_path, PA("strstr", []PArg{A("haystack", STRING), A("needle", STRING)})})
}
