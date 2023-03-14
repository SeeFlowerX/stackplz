// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package event_processor

import (
	"stackplz/user/event"
	"time"
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
	//events      []user.IEventStruct
	ticker      *time.Ticker
	tickerCount uint8
	UUID        string
	processor   *EventProcessor
	parser      IParser
	NeedExit    bool
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
	// 由 processer 变更
	this.NeedExit = false
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
	// this.processor.GetLogger().Printf("parserEvent UUID:%s", this.UUID)

	err := e.Decode()
	if err != nil {
		this.processor.GetLogger().Printf("Decode failed UUID:%s", this.UUID)
	}
	// 打印输出
	this.processor.GetLogger().Printf(e.String())

	// this.processor.GetLogger().Printf("%d %s", this.tickerCount, e.String())
	// 根据 event 选取对应的 解析器
	// parser := NewParser(e)
	// this.parser = parser

	// 写入payload到parser
	// _, err := this.parser.Write(e.Payload()[:e.PayloadLen()])
	// if err != nil {
	// 	this.processor.GetLogger().Fatalf("eventWorker: detect packet type error, UUID:%s, error:%v", this.UUID, err)
	// }

	// 是否接收完成，能否输出
	// if this.parser.IsDone() {
	// 	this.Display()
	// }
}

func (this *eventWorker) Run() {
	for {
		select {
		case _ = <-this.ticker.C:
			this.tickerCount++
			if this.NeedExit {
				this.Close()
				return
			}
		case e := <-this.incoming:
			this.parserEvent(e)
			if this.NeedExit {
				this.Close()
				return
			}
		}
	}
}

// func (this *eventWorker) Run() {
// 	for {
// 		select {
// 		case _ = <-this.ticker.C:
// 			// 输出包
// 			if this.tickerCount > MAX_TICKER_COUNT {
// 				this.processor.GetLogger().Printf("eventWorker TickerCount > %d, event closed.", MAX_TICKER_COUNT)
// 				this.Close()
// 				return
// 			}
// 			this.tickerCount++
// 		case e := <-this.incoming:
// 			// reset tickerCount
// 			this.tickerCount = 0
// 			this.parserEvent(e)
// 		}
// 	}
// }

func (this *eventWorker) Close() {
	// 即将关闭， 必须输出结果
	this.Display()
	this.tickerCount = 0
	this.processor.delWorkerByUUID(this)
}
