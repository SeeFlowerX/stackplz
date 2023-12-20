package config

type OpKeyConfig struct {
	OpCount   uint32
	OpKeyList [MAX_OP_COUNT]uint32
}

type ArgOpConfig struct {
	ArgName   string
	ArgValue  string
	OpKeyList []uint32
}

type PointArgsConfig struct {
	PointName    string
	ArgsSysEnter OpKeyConfig
	ArgsSysExit  OpKeyConfig
}

func X(arg_name string, arg_type ArgType) *ArgOpConfig {
	config := ArgOpConfig{}
	config.ArgName = arg_name
	// config.OpKeyList = arg_type.GetOps()
	return &config
}

func FillArgs(nr string, configs ...*ArgOpConfig) *OpKeyConfig {
	// 合并 op
	op_key_config := OpKeyConfig{}
	index := 0
	for _, config := range configs {
		for _, op_key := range config.OpKeyList {
			op_key_config.OpKeyList[index] = op_key
		}
	}
	return &op_key_config
}

func init() {
	FillArgs("sendmsg", X("sockfd", EXP_INT), X("msg", MSGHDR), X("flags", EXP_INT))
}
