package config

import (
	"fmt"
	"strconv"
)

type TableConfig struct {
	Count   uint32
	Name    string
	Mask    uint32
	RetMask uint32
}

type SysTableConfig map[string]TableConfig

func NewSysTableConfig() SysTableConfig {
	config := make(SysTableConfig)
	return config
}

func (this *SysTableConfig) GetNR(syscall string) (int, error) {
	target_nr := -1
	for nr, config := range *this {
		if config.Name == syscall {
			nr, _ := strconv.ParseUint(nr, 10, 32)
			target_nr = int(nr)
		}
	}
	if target_nr == -1 {
		return target_nr, fmt.Errorf("can not find nr for syscall:%s", syscall)
	}
	return target_nr, nil
}

func (this *SysTableConfig) GetName(nr uint32) string {
	nr_str := strconv.FormatUint(uint64(nr), 10)
	return (*this)[nr_str].Name
}

func (this *SysTableConfig) ReadNR(syscall_id uint32) string {
	nr_str := fmt.Sprintf("%d", syscall_id)
	return (*this)[nr_str].Name
}

func (this *SysTableConfig) ReadNRConfig(syscall_id uint32) TableConfig {
	nr_str := fmt.Sprintf("%d", syscall_id)
	return (*this)[nr_str]
}

func (this *SysTableConfig) CheckNR(nr uint32) error {
	// 检查系统调用号是否合法
	nr_str := strconv.FormatUint(uint64(nr), 10)
	has_nr := false
	for nr := range *this {
		if nr == nr_str {
			has_nr = true
			break
		}
	}
	if !has_nr {
		return fmt.Errorf("invalid nr:%d", nr)
	}
	return nil
}
