package config

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	. "stackplz/user/common"
)

type BrkPointConfig struct {
	ArgsStr    string
	PointArgs  []*PointArg
	DumpHex    bool
	DumpBase64 bool
	Color      bool
}

func (this *BrkPointConfig) IsEnable() bool {
	return len(this.PointArgs) > 0
}

func (this *BrkPointConfig) SetDumpHex(dumpHex bool) {
	this.DumpHex = dumpHex
}

func (this *BrkPointConfig) SetDumpBase64(dumpBase64 bool) {
	this.DumpBase64 = dumpBase64
}

func (this *BrkPointConfig) SetColor(color bool) {
	this.Color = color
}

func (this *BrkPointConfig) Parse_BrkPoint(configs []string) error {
	if len(configs) == 0 {
		return nil
	}
	parser := &StackUprobeConfig{}
	parser.SetDumpHex(this.DumpHex)
	parser.SetDumpBase64(this.DumpBase64)
	parser.SetColor(this.Color)

	var allArgs []string
	for _, configStr := range configs {
		configStr = strings.TrimSpace(configStr)
		if configStr == "" {
			continue
		}
		argsStr, err := extractBrkArgs(configStr)
		if err != nil {
			return err
		}
		for _, argStr := range strings.Split(argsStr, ",") {
			argStr = strings.TrimSpace(argStr)
			if argStr != "" {
				allArgs = append(allArgs, argStr)
			}
		}
	}

	this.ArgsStr = strings.Join(allArgs, ",")
	for argIndex, argStr := range allArgs {
		argName := fmt.Sprintf("arg_%d", argIndex)
		pointArg := NewUprobePointArg(argName, POINTER, uint32(argIndex))
		if err := parser.ParseArgType(argStr, pointArg); err != nil {
			return err
		}
		this.PointArgs = append(this.PointArgs, pointArg)
	}
	return nil
}

func extractBrkArgs(configStr string) (string, error) {
	if strings.HasPrefix(configStr, "[") && strings.HasSuffix(configStr, "]") {
		return strings.TrimSpace(configStr[1 : len(configStr)-1]), nil
	}

	reg := regexp.MustCompile(`\[(.+)\]`)
	match := reg.FindStringSubmatch(configStr)
	if len(match) == 2 {
		return strings.TrimSpace(match[1]), nil
	}

	if strings.Contains(configStr, "[") || strings.Contains(configStr, "]") {
		return "", errors.New(fmt.Sprintf("parse brk point args failed: %s", configStr))
	}
	return configStr, nil
}
