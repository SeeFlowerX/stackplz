//go:build !forarm
// +build !forarm

package argtype

import (
	"encoding/json"
	"fmt"
	"stackplz/user/util"
	"strings"
)

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

func (this *Arg_Timespec) MarshalJSON() ([]byte, error) {
	type ArgStructAlias Arg_struct
	return json.Marshal(&struct {
		*ArgStructAlias
		Sec  int64 `json:"sec"`
		Nsec int64 `json:"nsec"`
	}{
		ArgStructAlias: (*ArgStructAlias)(&this.Arg_struct),
		Sec:            this.Sec,
		Nsec:           this.Nsec,
	})
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
