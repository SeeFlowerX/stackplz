package event

import (
    "bytes"
    "encoding/binary"
    "fmt"
    "io/ioutil"

    "github.com/cilium/ebpf/perf"
)

type EventType uint8

const (
    // EventTypeModuleData set as module cache data
    EventTypeModuleData = 0
)

type IEventStruct interface {
    Decode() (err error)
    String() string
    Clone() IEventStruct
    EventType() EventType
    GetUUID() string
    // SetLogger(logger *log.Logger)
    // SetConf(conf config.IConfig)
    SetRecord(rec perf.Record)
}

type CommonEvent struct {
    // mconf *config.IConfig
    rec perf.Record
    buf *bytes.Buffer
}

func (this *CommonEvent) SetRecord(rec perf.Record) {
    this.rec = rec
}

// func (this *CommonEvent) SetConf(conf config.IConfig) {
//     panic("CommonEvent.SetConf() can not cast")
// }

func (this *CommonEvent) ParsePadding() (err error) {
    padding_size := this.rec.SampleSize + 4 - uint32(this.buf.Cap()-this.buf.Len())
    if padding_size > 0 {
        payload := make([]byte, padding_size)
        if err = binary.Read(this.buf, binary.LittleEndian, &payload); err != nil {
            // this.logger.Printf("ContextEvent EventId:%d RawSample:\n%s", this.EventId, util.HexDump(this.rec.RawSample, util.COLORRED))
            panic(fmt.Sprintf("binary.Read err:%v", err))
        }
    }
    return nil
}

type LibArg struct {
    Abi       uint64
    Regs      [33]uint64
    StackSize uint64
    DynSize   uint64
}

type UnwindBuf struct {
    Abi       uint64
    Regs      [33]uint64
    StackSize uint64
    Data      []byte
    DynSize   uint64
}

func (this *UnwindBuf) GetLibArg() *LibArg {
    arg := &LibArg{}
    arg.Abi = this.Abi
    arg.Regs = this.Regs
    arg.StackSize = this.StackSize
    arg.DynSize = this.DynSize
    return arg
}

func (this *UnwindBuf) ParseContext(buf *bytes.Buffer) (err error) {
    if err = binary.Read(buf, binary.LittleEndian, &this.Abi); err != nil {
        return err
    }
    if err = binary.Read(buf, binary.LittleEndian, &this.Regs); err != nil {
        return err
    }
    if err = binary.Read(buf, binary.LittleEndian, &this.StackSize); err != nil {
        return err
    }

    stack_data := make([]byte, this.StackSize)
    if err = binary.Read(buf, binary.LittleEndian, &stack_data); err != nil {
        return err
    }
    this.Data = stack_data

    if err = binary.Read(buf, binary.LittleEndian, &this.DynSize); err != nil {
        return err
    }
    return nil
}

type RegsBuf struct {
    Abi  uint64
    Regs [33]uint64
}

func (this *RegsBuf) ParseContext(buf *bytes.Buffer) (err error) {
    if err = binary.Read(buf, binary.LittleEndian, &this.Abi); err != nil {
        return err
    }
    if err = binary.Read(buf, binary.LittleEndian, &this.Regs); err != nil {
        return err
    }
    return nil
}

func ReadMapsByPid(pid uint32) (string, error) {
    filename := fmt.Sprintf("/proc/%d/maps", pid)
    content, err := ioutil.ReadFile(filename)
    if err != nil {
        return "", err
    }
    return string(content), nil
}
