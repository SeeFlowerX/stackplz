package event

import (
    "bytes"
    "encoding/binary"
    "encoding/json"
    "fmt"
    "stackplz/user/config"
    "stackplz/user/util"
)

type CommEvent struct {
    CommonEvent
    config.CommFields
}

func (this *CommEvent) String() string {
    if this.mconf.FmtJson {
        data, err := json.Marshal(&this.CommFields)
        if err != nil {
            panic(err)
        }
        return string(data)
    }
    var s string
    s = fmt.Sprintf("[CommEvent] %s", this.GetUUID())
    return s
}

func (this *CommEvent) GetUUID() string {
    return fmt.Sprintf("%d_%d_%s", this.Pid, this.Tid, this.Comm)
}

func (this *CommEvent) ParseContext() (err error) {
    this.buf = bytes.NewBuffer(this.rec.RawSample)
    if err = binary.Read(this.buf, binary.LittleEndian, &this.Pid); err != nil {
        return err
    }
    // 来源于自己的通通不管
    if this.mconf.SelfPid == this.Pid {
        return nil
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.Tid); err != nil {
        return err
    }
    var tmp = make([]byte, this.buf.Len())
    if err = binary.Read(this.buf, binary.LittleEndian, &tmp); err != nil {
        return err
    }
    this.Comm = util.B2STrim(tmp)
    if this.mconf.Debug {
        this.logger.Printf(this.String())
    }
    return nil
}
