package event

import (
    "bytes"
    "encoding/binary"
    "fmt"
    "stackplz/pkg/util"
)

type CommEvent struct {
    CommonEvent
    Pid       uint32
    Tid       uint32
    Comm      string
    Sample_id []byte
}

func (this *CommEvent) Decode() (err error) {
    var tmp = make([]byte, this.buf.Len())
    if err = binary.Read(this.buf, binary.LittleEndian, &tmp); err != nil {
        return err
    }
    this.Comm = util.B2STrim(tmp)
    return nil
}

func (this *CommEvent) String() string {
    var s string
    s = fmt.Sprintf("[PERF_RECORD_COMM] %s", this.GetUUID())
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
    if err = binary.Read(this.buf, binary.LittleEndian, &this.Tid); err != nil {
        return err
    }
    return nil
}
