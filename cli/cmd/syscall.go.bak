/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
    "context"
    "io"
    "log"
    "os"
    "os/signal"
    "stackplz/user/config"
    "stackplz/user/module"
    "sync"
    "syscall"

    "github.com/spf13/cobra"
)

var syscall_config = config.NewSyscallConfig()

var syscallCmd = &cobra.Command{
    Use:   "syscall",
    Short: "filter and show syscall stack plz",
    Long:  "filter and show syscall stack which based unwindstack",
    // Run:   syscallCommandFunc,
}

func init() {
    // 此处 stack_config 只是设置了默认的值
    // gconfig 也是只设置了默认的值
    syscallCmd.PersistentFlags().BoolVarP(&syscall_config.UnwindStack, "stack", "", false, "enable unwindstack")
    syscallCmd.PersistentFlags().BoolVarP(&syscall_config.ShowRegs, "regs", "", false, "show regs")
    syscallCmd.PersistentFlags().StringVar(&syscall_config.Config, "config", "", "syscall hook config file")
    syscallCmd.PersistentFlags().Int64VarP(&syscall_config.NR, "nr", "", -1, "filter syscall number")
    // rootCmd.AddCommand(syscallCmd)
}

func syscallCommandFunc(command *cobra.Command, args []string) {
    stopper := make(chan os.Signal, 1)
    signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
    ctx, cancelFun := context.WithCancel(context.TODO())

    // 首先根据全局设定设置日志输出
    logger := log.New(os.Stdout, "syscall_", log.Ltime)
    if gconfig.LogFile != "" {
        log_path := "/data/local/tmp/" + gconfig.LogFile
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
        if gconfig.Quiet {
            // 直接设置 则不会输出到终端
            logger.SetOutput(f)
        } else {
            // 这样可以同时输出到终端
            mw := io.MultiWriter(os.Stdout, f)
            logger.SetOutput(mw)
        }
    }

    sysnoConfigs := []int64{syscall_config.NR}

    var runMods uint8
    var runModules = make(map[string]module.IModule)
    var wg sync.WaitGroup

    for _, sysno := range sysnoConfigs {

        sysnoConfig := config.SyscallConfig{
            SConfig: config.SConfig{
                UnwindStack: syscall_config.UnwindStack,
                ShowRegs:    syscall_config.ShowRegs,
                Uid:         gconfig.Uid,
                Pid:         gconfig.Pid,
                // TidsBlacklist:     target_config.TidsBlacklist,
                // TidsBlacklistMask: target_config.TidsBlacklistMask,
            },
            NR: sysno,
        }

        mod := module.GetModuleByName(module.MODULE_NAME_SYSCALL)

        if mod == nil {
            logger.Printf("cant found module: %s", module.MODULE_NAME_SYSCALL)
            break
        }

        logger.Printf("%s\thook nr:%d", mod.Name(), sysnoConfig.NR)

        err := mod.Init(ctx, logger, &sysnoConfig)
        if err != nil {
            logger.Printf("%s\tmodule Init failed, [skip it]. error:%+v", mod.Name(), err)
            continue
        }
        err = mod.Run()
        if err != nil {
            logger.Printf("%s\tmodule Run failed, [skip it]. error:%+v", mod.Name(), err)
            continue
        }
        runModules[sysnoConfig.Info()] = mod
        if gconfig.Debug {
            logger.Printf("%s\tmodule started successfully", mod.Name())
        }
        wg.Add(1)
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
