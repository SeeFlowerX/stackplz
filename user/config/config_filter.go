package config

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"stackplz/user/common"
	"stackplz/user/util"
	"strings"
)

type ConfigMap struct {
	stackplz_pid     uint32
	thread_whitelist uint32
}

type CommonFilter struct {
	is_32bit        uint32
	trace_mode      uint32
	trace_uid_group uint32
	signal          uint32
	tsignal         uint32
}

type ThreadFilter struct {
	ThreadName [16]byte
}

const (
	UNKNOWN_FILTER uint32 = iota
	EQUAL_FILTER
	GREATER_FILTER
	LESS_FILTER
	WHITELIST_FILTER
	BLACKLIST_FILTER
	REPLACE_FILTER
)

type ArgFilter struct {
	Filter_str   string
	Filter_type  uint32
	Filter_index uint32
	Num_val      uint64
	Str_val      [256]byte
	Str_len      uint32
}

func (this *ArgFilter) Match(name string) bool {
	if this.Filter_index == 0 {
		return false
	}
	return name == fmt.Sprintf("f%d", this.Filter_index-1)
}

func (this *ArgFilter) IsStr() bool {
	return this.Filter_type == WHITELIST_FILTER || this.Filter_type == BLACKLIST_FILTER
}

func (this *ArgFilter) ToEbpfValue() EArgFilter {
	t := EArgFilter{}
	t.Filter_type = this.Filter_type
	t.Str_len = this.Str_len
	t.Str_val = this.Str_val
	t.Num_val = this.Num_val
	return t
}

type EArgFilter struct {
	Filter_type uint32
	Str_val     [common.MAX_STRCMP_LEN]byte
	Str_len     uint32
	Num_val     uint64
}

type FilterHelper struct {
	filters []ArgFilter
}

func (this *FilterHelper) GetFilters() []ArgFilter {
	return this.filters
}

func (this *FilterHelper) GetFilterByName(filter_name string) ArgFilter {
	for _, f := range this.filters {
		if f.Match(filter_name) {
			return f
		}
	}
	panic(fmt.Sprintf("%s not match any filter", filter_name))
}

func (this *FilterHelper) GetFilterIndex(filter string) uint32 {
	arg_filter := this.GetFilterByName(filter)
	return arg_filter.Filter_index
}

func (this *FilterHelper) AddFilter(filter string) uint32 {
	for _, f := range this.filters {
		if f.Filter_str == filter {
			return f.Filter_index
		}
	}
	arg_filter := ArgFilter{}
	items := strings.SplitN(filter, ":", 2)
	if len(items) != 2 {
		panic(fmt.Sprintf("AddFilter failed, filter:%s", filter))
	}
	switch items[0] {
	case "bx", "bufhex":
		arg_filter.Filter_type = WHITELIST_FILTER
		str_old, err := hex.DecodeString(items[1])
		if err != nil {
			panic(fmt.Sprintf("hex string to bytes failed => %s", items[1]))
		}
		if len(str_old) > 8 {
			panic(fmt.Sprintf("hex string is to long, max bytes length is 8"))
		}
		arg_filter.Str_len = (8 - uint32(len(str_old))) * 8
		arg_filter.Num_val = util.StrToNum64("0x" + items[1])
		data := make([]byte, 8)
		binary.BigEndian.PutUint64(data, arg_filter.Num_val)
		arg_filter.Num_val = binary.LittleEndian.Uint64(data) >> arg_filter.Str_len
	case "eq", "equal":
		arg_filter.Filter_type = EQUAL_FILTER
		arg_filter.Num_val = util.StrToNum64(items[1])
	case "gt", "greater":
		arg_filter.Filter_type = GREATER_FILTER
		arg_filter.Num_val = util.StrToNum64(items[1])
	case "lt", "less":
		arg_filter.Filter_type = LESS_FILTER
		arg_filter.Num_val = util.StrToNum64(items[1])
	case "w", "white":
		arg_filter.Filter_type = WHITELIST_FILTER
		str_old := []byte(items[1])
		if len(str_old) > 256 {
			panic(fmt.Sprintf("string is to long, max length is 256"))
		}
		arg_filter.Str_len = uint32(len(str_old))
		copy(arg_filter.Str_val[:], str_old)
	case "b", "black":
		arg_filter.Filter_type = BLACKLIST_FILTER
		str_old := []byte(items[1])
		if len(str_old) > 256 {
			panic(fmt.Sprintf("string is to long, max length is 256"))
		}
		arg_filter.Str_len = uint32(len(str_old))
		copy(arg_filter.Str_val[:], str_old)
	default:
		panic(fmt.Sprintf("AddFilter failed, unknown filter type:%s", items[0]))
	}
	arg_filter.Filter_index = uint32(len(this.filters) + 1)
	this.filters = append(this.filters, arg_filter)
	return arg_filter.Filter_index
}

func NewFilterHelper() *FilterHelper {
	helper := &FilterHelper{}
	return helper
}

var filter_helper = NewFilterHelper()

func GetFilterIndex(filter string) uint32 {
	return filter_helper.GetFilterIndex(filter)
}

func AddFilter(filter string) uint32 {
	return filter_helper.AddFilter(filter)
}

func GetFilters() []ArgFilter {
	return filter_helper.GetFilters()
}

func GetFilterByName(name string) ArgFilter {
	return filter_helper.GetFilterByName(name)
}
