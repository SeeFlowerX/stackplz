/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
    "context"
    "encoding/json"
    "fmt"
    "io"
    "io/ioutil"
    "log"
    "os"
    "os/signal"
    "stackplz/pkg/util"
    "stackplz/user/config"
    "stackplz/user/module"
    "strconv"
    "strings"
    "sync"
    "syscall"

    "github.com/spf13/cobra"
    "golang.org/x/exp/slices"
)

type BaseHookConfig struct {
    Unwindstack bool     `json:"unwindstack"`
    Regs        bool     `json:"regs"`
    Symbols     []string `json:"symbols"`
    Offsets     []string `json:"offsets"`
}

type LibHookConfig struct {
    Library string           `json:"library"`
    Disable bool             `json:"disable"`
    Configs []BaseHookConfig `json:"configs"`
}

type HookConfig struct {
    LibraryDirs []string        `json:"library_dirs"`
    Libs        []LibHookConfig `json:"libs"`
}

func hex2int(hexStr string) uint64 {
    cleaned := strings.Replace(hexStr, "0x", "", -1)
    result, _ := strconv.ParseUint(cleaned, 16, 64)
    return uint64(result)
}

var stack_config = config.NewStackConfig()

var stackCmd = &cobra.Command{
    Use:   "stack",
    Short: "show stack plz",
    Long:  "show stack which based unwindstack",
    Run:   stackCommandFunc,
}

func init() {
    // 此处 stack_config 只是设置了默认的值
    // global_config 也是只设置了默认的值
    stackCmd.PersistentFlags().BoolVarP(&stack_config.UnwindStack, "unwindstack", "", false, "enable unwindstack")
    stackCmd.PersistentFlags().BoolVarP(&stack_config.ShowRegs, "regs", "", false, "show regs")
    stackCmd.PersistentFlags().StringVar(&stack_config.Library, "library", "/apex/com.android.runtime/lib64/bionic/libc.so", "full lib path")
    stackCmd.PersistentFlags().StringVar(&stack_config.Symbol, "symbol", "", "lib symbol")
    stackCmd.PersistentFlags().Uint64Var(&stack_config.Offset, "offset", 0, "lib hook offset")
    stackCmd.PersistentFlags().StringVar(&stack_config.Config, "config", "", "hook config file")
    rootCmd.AddCommand(stackCmd)
}

func stackCommandFunc(command *cobra.Command, args []string) {
    stopper := make(chan os.Signal, 1)
    signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
    ctx, cancelFun := context.WithCancel(context.TODO())

    // 首先根据全局设定设置日志输出
    logger := log.New(os.Stdout, "stack_", log.LstdFlags)
    if global_config.LoggerFile != "" {
        log_path := global_config.ExecPath + "/" + global_config.LoggerFile
        _, err := os.Stat(log_path)
        if err != nil {
            if os.IsNotExist(err) {
                os.Remove(log_path)
            }
        }
        f, err := os.Create(log_path)
        if err != nil {
            logger.Fatal(err)
            os.Exit(1)
        }
        if global_config.Quiet {
            // 直接设置 则不会输出到终端
            logger.SetOutput(f)
        } else {
            // 这样可以同时输出到终端
            mw := io.MultiWriter(os.Stdout, f)
            logger.SetOutput(mw)
        }
    }
    // uprobe hook 列表
    var probeConfigs []config.ProbeConfig
    // 指定配置文件
    if stack_config.Config != "" {
        parseConfig(logger, stack_config.Config, &probeConfigs)
    } else {
        library, err := util.FindLib(stack_config.Library, target_config.LibraryDirs)
        if err != nil {
            logger.Fatal(err)
            os.Exit(1)
        }
        // 没有配置文件 尝试检查是不是通过命令行进行单个位置点hook
        pConfig := config.ProbeConfig{
            Library: library,
            Symbol:  stack_config.Symbol,
            Offset:  stack_config.Offset,
            SConfig: config.SConfig{
                UnwindStack: stack_config.UnwindStack,
                ShowRegs:    stack_config.ShowRegs,
                Uid:         target_config.Uid,
            },
        }
        if err := pConfig.Check(); err == nil {
            probeConfigs = append(probeConfigs, pConfig)
        } else {
            logger.Fatal(err)
            os.Exit(1)
        }
    }

    // 预设stack命令下全部的模块名
    // modNames := []string{module.MODULE_NAME_STACK}

    var runMods uint8
    var runModules = make(map[string]module.IModule)
    var wg sync.WaitGroup

    for _, probeConfig := range probeConfigs {
        mod := module.GetModuleByName(module.MODULE_NAME_STACK)

        if mod == nil {
            logger.Printf("cant found module: %s", module.MODULE_NAME_STACK)
            break
        }

        probeConfig.Debug = global_config.Debug

        logger.Printf("%s\thook info:%s", mod.Name(), probeConfig.Info())

        // 初始化单个eBPF模块
        err := mod.Init(ctx, logger, &probeConfig)
        if err != nil {
            logger.Printf("%s\tmodule Init failed, [skip it]. error:%+v", mod.Name(), err)
            continue
        }
        // 执行模块
        err = mod.Run()
        if err != nil {
            logger.Printf("%s\tmodule Run failed, [skip it]. error:%+v", mod.Name(), err)
            continue
        }
        runModules[probeConfig.Info()] = mod
        if global_config.Debug {
            logger.Printf("%s\tmodule started successfully", mod.Name())
        }
        wg.Add(1)
        // 计数
        runMods++
    }

    if runMods > 0 {
        logger.Printf("start %d modules", runMods)
        <-stopper
    } else {
        logger.Println("No runnable modules, Exit(1)")
        os.Exit(1)
    }
    cancelFun()

    // clean up
    for _, mod := range runModules {
        err := mod.Close()
        wg.Done()
        if err != nil {
            logger.Fatalf("%s:module close failed, Info:%s. error:%+v", mod.Name(), mod.GetConf(), err)
        }
    }

    wg.Wait()
    os.Exit(0)
}

func parseConfig(logger *log.Logger, config_path string, probeConfigs *[]config.ProbeConfig) error {
    // 以 / 开头的当作全路径读取
    if !strings.HasPrefix(config_path, "/") {
        // 否则先检查是否直接存在
        if _, err := os.Stat(config_path); err != nil {
            // 不存在则尝试拼接可执行程序所在文件夹路径
            config_path = global_config.ExecPath + "/" + config_path
        }
    }

    content, err := ioutil.ReadFile(config_path)
    if err != nil {
        return fmt.Errorf("Error when opening file:%v", err)
    }
    // 按特定格式解析
    var hookConfig HookConfig
    json.Unmarshal(content, &hookConfig)

    hookConfig.LibraryDirs = append(hookConfig.LibraryDirs, target_config.LibraryDirs...)
    for _, libHookConfig := range hookConfig.Libs {
        if libHookConfig.Disable {
            if global_config.Debug {
                logger.Printf("disabled, skip hook %s", libHookConfig.Library)
            }
            continue
        }
        // 先查找目标库
        library, err := util.FindLib(libHookConfig.Library, hookConfig.LibraryDirs)
        // 找不到 重复 ... 直接结束并返回错误
        // 或者考虑提供一个选项允许跳过找不到的 只对找得到的hook
        if err != nil {
            return err
        }
        // 用于对每个库的配置去重
        var symbols []string
        var offsets []string
        for _, baseHookConfig := range libHookConfig.Configs {
            // 按符号
            for _, symbol := range baseHookConfig.Symbols {
                if strings.Trim(symbol, " ") == "" {
                    continue
                }
                // 符号去重
                if slices.Contains(symbols, symbol) {
                    logger.Printf("duplicated symbol:%s", symbol)
                    continue
                } else {
                    symbols = append(symbols, symbol)
                }
                pConfig := config.ProbeConfig{
                    SConfig: config.SConfig{
                        UnwindStack: baseHookConfig.Unwindstack,
                        ShowRegs:    baseHookConfig.Regs,
                        Uid:         target_config.Uid,
                    },
                    Library: library,
                    Symbol:  symbol,
                    Offset:  0,
                }
                if err := pConfig.Check(); err == nil {
                    *probeConfigs = append(*probeConfigs, pConfig)
                } else {
                    logger.Fatal(err)
                    os.Exit(1)
                }
            }
            // 按偏移
            for _, offset := range baseHookConfig.Offsets {
                if strings.Trim(offset, " ") == "" {
                    continue
                }
                // 偏移必须以 0x 开头
                if !strings.HasPrefix(offset, "0x") {
                    logger.Printf("must start with 0x, offset:%s", offset)
                    continue
                }
                // 偏移去重
                if slices.Contains(offsets, offset) {
                    logger.Printf("duplicated offset:%s", offset)
                    continue
                } else {
                    offsets = append(offsets, offset)
                }
                pConfig := config.ProbeConfig{
                    SConfig: config.SConfig{
                        UnwindStack: baseHookConfig.Unwindstack,
                        ShowRegs:    baseHookConfig.Regs,
                        Uid:         target_config.Uid,
                    },
                    Library: library,
                    Symbol:  "",
                    Offset:  hex2int(offset),
                }
                if err := pConfig.Check(); err == nil {
                    *probeConfigs = append(*probeConfigs, pConfig)
                } else {
                    logger.Fatal(err)
                    os.Exit(1)
                }
            }
        }
    }
    if global_config.Debug {
        logger.Printf("hook count %d", len(*probeConfigs))
    }
    return nil
}
