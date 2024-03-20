//go:build forarm
// +build forarm

package argtype

import (
	"encoding/json"
	"fmt"
	"stackplz/user/util"
	"strings"
)

type Utsname struct {
	Sysname    [65]uint8
	Nodename   [65]uint8
	Release    [65]uint8
	Version    [65]uint8
	Machine    [65]uint8
	Domainname [65]uint8
}

type Timespec struct {
	Sec  int32
	Nsec int32
}

func (this *Arg_Timespec) MarshalJSON() ([]byte, error) {
	type ArgStructAlias Arg_struct
	return json.Marshal(&struct {
		*ArgStructAlias
		Sec  int32 `json:"sec"`
		Nsec int32 `json:"nsec"`
	}{
		ArgStructAlias: (*ArgStructAlias)(&this.Arg_struct),
		Sec:            this.Sec,
		Nsec:           this.Nsec,
	})
}

func (this *Arg_Utsname) Format() string {
	var fields []string
	fields = append(fields, fmt.Sprintf("sysname=%s", util.UB2S(this.Sysname[:])))
	fields = append(fields, fmt.Sprintf("nodename=%s", util.UB2S(this.Nodename[:])))
	fields = append(fields, fmt.Sprintf("release=%s", util.UB2S(this.Release[:])))
	fields = append(fields, fmt.Sprintf("version=%s", util.UB2S(this.Version[:])))
	fields = append(fields, fmt.Sprintf("machine=%s", util.UB2S(this.Machine[:])))
	fields = append(fields, fmt.Sprintf("domainname=%s", util.UB2S(this.Domainname[:])))
	return fmt.Sprintf("{%s}", strings.Join(fields, ", "))
}
