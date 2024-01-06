package event

import (
    "bytes"
    "encoding/binary"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "stackplz/user/config"
    "strings"

    "golang.org/x/exp/slices"
)

type ForkEvent struct {
    CommonEvent
    config.ForkFields
}

func (this *ForkEvent) String() string {
    if this.mconf.FmtJson {
        data, err := json.Marshal(&this.ForkFields)
        if err != nil {
            panic(err)
        }
        return string(data)
    }

    var s string
    s = fmt.Sprintf("[ForkEvent] %s ppid=%d ptid=%d time=%d", this.GetUUID(), this.Ppid, this.Ptid, this.Time)
    return s
}

func (this *ForkEvent) GetUUID() string {
    return fmt.Sprintf("%d_%d", this.Pid, this.Tid)
}

func (this *ForkEvent) ParseContext() (err error) {
    this.buf = bytes.NewBuffer(this.rec.RawSample)
    if err = binary.Read(this.buf, binary.LittleEndian, &this.Pid); err != nil {
        return err
    }
    // 来源于自己的通通不管
    if this.mconf.SelfPid == this.Pid {
        return nil
    }
    this.ReadValue(&this.Ppid)
    this.ReadValue(&this.Tid)
    this.ReadValue(&this.Ptid)
    this.ReadValue(&this.Time)
    if this.mconf.Debug {
        this.logger.Printf(this.String())
    }

    if slices.Contains(this.mconf.PidWhitelist, this.Pid) {
        maps_helper.UpdateForkEvent(this)
        return nil
    }
    proc_name, err := ReadProcNameByPid(this.Pid)
    if slices.Contains(this.mconf.PkgNamelist, proc_name) {
        maps_helper.UpdateForkEvent(this)
    }
    return nil
}

func ReadProcNameByPid(pid uint32) (string, error) {
    filename := fmt.Sprintf("/proc/%d/cmdline", pid)
    content, err := ioutil.ReadFile(filename)
    if err != nil {
        return "", err
    }
    cmdline := string(bytes.TrimSpace(bytes.Trim(content, "\x00")))
    items := strings.SplitN(cmdline, ":", 2)
    return items[0], nil
}
