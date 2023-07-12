package event

import (
    "bytes"
    "encoding/binary"
    "fmt"
    "stackplz/pkg/util"
)

type CommEvent struct {
    CommonEvent
    pid       uint32
    tid       uint32
    comm      string
    sample_id []byte
}

func (this *CommEvent) Decode() (err error) {
    var tmp = make([]byte, this.buf.Len())
    if err = binary.Read(this.buf, binary.LittleEndian, &tmp); err != nil {
        return err
    }
    this.comm = util.B2STrim(tmp)
    return nil
}

func (this *CommEvent) String() string {
    var s string
    s = fmt.Sprintf("[PERF_RECORD_COMM] %s", this.GetUUID())
    return s
}

func (this *CommEvent) GetUUID() string {
    return fmt.Sprintf("%d_%d_%s", this.pid, this.tid, this.comm)
}

func (this *CommEvent) ParseContext() (err error) {
    this.buf = bytes.NewBuffer(this.rec.RawSample)
    if err = binary.Read(this.buf, binary.LittleEndian, &this.pid); err != nil {
        return err
    }
    if err = binary.Read(this.buf, binary.LittleEndian, &this.tid); err != nil {
        return err
    }
    return nil
}
