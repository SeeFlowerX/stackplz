package config

import (
	"fmt"
	"stackplz/user/argtype"
	. "stackplz/user/common"
	"strconv"
	"strings"
)

type ParamConfig struct {
	Name   string   `json:"name"`
	Type   string   `json:"type"`
	Format string   `json:"format"`
	Size   string   `json:"size"`
	More   string   `json:"more"`
	Filter []string `json:"filter"`
	Reg    string   `json:"reg"`
	ReadOp string   `json:"read_op"`
}

type PointConfig struct {
	Name   string        `json:"name"`
	Signal string        `json:"signal"`
	Params []ParamConfig `json:"params"`
}

type SyscallPointConfig struct {
	Nr uint32 `json:"nr"`
	PointConfig
}

type IFileConfig interface {
	GetType() string
}

type FileConfig struct {
	Type string `json:"type"`
}

func (this *FileConfig) GetType() string {
	return this.Type
}

func (this *ParamConfig) GetPointArg(arg_index uint32) *PointArg {
	// 参数名省略时 以 a{index} 这样的形式作为名字
	arg_name := fmt.Sprintf("a%d", arg_index)
	if this.Name != "" {
		arg_name = this.Name
	}
	// 默认以参数索引作为寄存器索引 除非特别指定寄存器
	// 若通过 read_op 指定读取地址 后面根据 ExtraOpList 决定是否使用这里的索引
	reg_index := arg_index
	if this.Reg != "" {
		reg_index = GetRegIndex(this.Reg)
	}
	// 基础配置
	point_arg := NewUprobePointArg(arg_name, POINTER, reg_index)
	// 先处理一些比较特殊的情况

	to_ptr := false
	type_name := this.Type
	if strings.HasPrefix(type_name, "*") {
		to_ptr = true
		type_name = type_name[1:]
	}

	switch type_name {
	case "buf":
		// buf 类型需要给定读取的大小 但是这个大小有可能是通过寄存器指定
		at := argtype.R_BUFFER_LEN(256)
		if this.Size != "" {
			size, err := strconv.ParseUint(this.Size, 0, 32)
			if err == nil {
				// 以指定长度作为读取大小
				at = argtype.R_BUFFER_LEN(uint32(size))
			} else {
				// 以寄存器的值作为读取大小
				at = argtype.R_BUFFER_REG(GetRegIndex(this.Size))
			}
		}
		point_arg.SetTypeIndex(at.GetTypeIndex())
		// 这个设定用于指示是否进一步读取和解析
		point_arg.SetGroupType(EBPF_UPROBE_ENTER)
	case "int_arr", "uint_arr", "ptr_arr":
		// 必须指定数组长度
		size, err := strconv.ParseUint(this.Size, 0, 32)
		if err != nil {
			panic(fmt.Sprintf("parse %s array size failed", type_name))
		}
		var at argtype.IArgType
		if type_name == "int_arr" {
			at = argtype.R_NUM_ARRAY(INT, uint32(size))
		} else if type_name == "uint_arr" {
			at = argtype.R_NUM_ARRAY(UINT, uint32(size))
		} else {
			at = argtype.R_NUM_ARRAY(UINT64, uint32(size))
		}
		point_arg.SetTypeIndex(at.GetTypeIndex())
		point_arg.SetGroupType(EBPF_UPROBE_ENTER)
	case "str", "std":
		// 根据名称指定类型
		// 支持自定义类型 但是需要提前在配置文件中写好
		point_arg.SetTypeByName(type_name)
		point_arg.SetGroupType(EBPF_UPROBE_ENTER)
	case "int", "uint", "int8", "uint8", "int16", "uint16", "int32", "uint32", "int64", "uint64":
		point_arg.SetTypeByName(type_name)
	default:
		// 上面两个case可以合并 这样写只是为了做出区分
		point_arg.SetTypeByName(type_name)
	}

	// 有一层指针的情形 配置中在类型最前面加*即可 不需要额外定义
	if to_ptr {
		point_arg.ToPointerType()
		point_arg.SetGroupType(EBPF_UPROBE_ENTER)
	}

	switch this.Format {
	case "hex":
		point_arg.SetHexFormat()
	case "hexdump":
		point_arg.SetHexFormat()
	}

	// 设置过滤规则 先解析规则 然后取到规则索引
	for _, v := range this.Filter {
		point_arg.AddFilterIndex(GetFilterIndex(v))
	}

	// ./stackplz -n com.termux -l libtest.so -w 0x16254[buf:64:sp+0x20-0x8.+8.-4+0x16]
	// read_op_str -> "sp+0x20-0x8.+8.-4+0x16"
	// 该命令含义为
	// 1. 在 libtest.so 偏移 0x16254 处hook
	// 2. 计算 sp+0x20-0x8 后读取指针
	// 3. 在上一步结果上 +8 后读取指针
	// 4. 在上一步结果上 -4+0x16
	// 5. 以上一步结果作为读取地址 读取 64 字节数据
	if this.ReadOp != "" {
		// 即一系列 加、减、取指针 操作作为要读取类型的地址 通过以下规则来转换
		has_first_op := false
		for ptr_idx, op_str := range strings.Split(this.ReadOp, ".") {
			if ptr_idx > 0 {
				point_arg.AddExtraOp(argtype.OPC_READ_POINTER)
				point_arg.AddExtraOp(argtype.OPC_MOVE_POINTER_VALUE)
			}
			if op_str == "" {
				continue
			}
			v := op_str + "+"
			last_op := ""
			for {
				i := strings.IndexAny(v, "+-")
				if i < 0 {
					break
				}
				op := string(v[i])
				token := string(v[0:i])
				v = v[i+1:]
				if token != "" {
					if value, err := strconv.ParseUint(token, 0, 64); err == nil {
						if !has_first_op {
							panic(fmt.Sprintf("first op must be reg"))
						}
						if last_op == "-" {
							point_arg.AddExtraOp(argtype.OPC_SUB_OFFSET.NewValue(value))
						} else {
							point_arg.AddExtraOp(argtype.OPC_ADD_OFFSET.NewValue(value))
						}
					} else {
						reg_index := GetRegIndex(token)
						point_arg.AddExtraOp(argtype.Add_READ_MOVE_REG(uint64(reg_index)))
						if has_first_op {
							if last_op == "-" {
								point_arg.AddExtraOp(argtype.OPC_SUB_REG)
							} else {
								point_arg.AddExtraOp(argtype.OPC_ADD_REG)
							}
						}
						if !has_first_op {
							has_first_op = true
						}
					}
				}
				last_op = op
			}
		}
		point_arg.AddExtraOp(argtype.OPC_SAVE_ADDR)
	}
	return point_arg
}

type UprobeFileConfig struct {
	FileConfig
	Library string        `json:"library"`
	Points  []PointConfig `json:"points"`
}

type SyscallFileConfig struct {
	FileConfig
	Points []SyscallPointConfig `json:"points"`
}
