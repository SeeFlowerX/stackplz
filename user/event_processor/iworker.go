package event_processor

import (
	"stackplz/user/event"
	"time"

	"golang.org/x/sys/unix"
)

type IWorker interface {

	// 定时器1 ，定时判断没有后续包，则解析输出

	// 定时器2， 定时判断没后续包，则通知上层销毁自己

	// 收包
	Write(event.IEventStruct) error
	GetUUID() string
}

const (
	MAX_TICKER_COUNT = 10  // 1 Sencond/(eventWorker.ticker.C) = 10
	MAX_CHAN_LEN     = 256 // 包队列长度
	//MAX_EVENT_LEN    = 16 // 事件数组长度
)

type eventWorker struct {
	incoming chan event.IEventStruct
	// last_event event.IEventStruct
	//events      []user.IEventStruct
	ticker      *time.Ticker
	tickerCount uint8
	UUID        string
	processor   *EventProcessor
}

func NewEventWorker(uuid string, processor *EventProcessor) IWorker {
	eWorker := &eventWorker{}
	eWorker.init(uuid, processor)
	go func() {
		eWorker.Run()
	}()
	return eWorker
}

func (this *eventWorker) init(uuid string, processor *EventProcessor) {
	this.ticker = time.NewTicker(time.Millisecond * 100)
	this.incoming = make(chan event.IEventStruct, MAX_CHAN_LEN)
	this.UUID = uuid
	this.processor = processor
}

func (this *eventWorker) GetUUID() string {
	return this.UUID
}

func (this *eventWorker) Write(e event.IEventStruct) error {
	this.incoming <- e
	return nil
}

// 输出包内容
func (this *eventWorker) Display() {

}

// 解析类型，输出
func (this *eventWorker) parserEvent(e event.IEventStruct) {
	logger := this.processor.GetLogger()
	err := e.Decode()
	if err != nil {
		logger.Printf("Decode failed UUID:%s, err:%v", this.UUID, err)
	}
	switch e.RecordType() {
	case unix.PERF_RECORD_COMM:
	case unix.PERF_RECORD_MMAP2:
	case unix.PERF_RECORD_EXIT:
	case unix.PERF_RECORD_FORK:
		{
			// 这几种暂时不需要输出
			break
		}
	default:
		{
			logger.Printf(e.String())
		}
	}

}

func (this *eventWorker) Run() {
	for {
		select {
		case _ = <-this.ticker.C:
			if this.tickerCount > MAX_TICKER_COUNT {
				this.Close()
				return
			}
			this.tickerCount++
		case e := <-this.incoming:
			// reset tickerCount
			this.tickerCount = 0
			this.parserEvent(e)
		}
	}
}

func (this *eventWorker) Close() {
	// 即将关闭， 必须输出结果
	this.Display()
	this.tickerCount = 0
	this.processor.delWorkerByUUID(this)
}
