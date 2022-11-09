/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
    "context"
    "edemo/user/config"
    "edemo/user/module"
    "io"
    "log"
    "os"
    "os/signal"
    "path"
    "sync"
    "syscall"

    "github.com/spf13/cobra"
)

var stack_config = config.NewStackConfig()

var stackCmd = &cobra.Command{
    Use:   "stack",
    Short: "show stack plz",
    Long:  "show stack which based unwindstack",
    Run:   stackCommandFunc,
}

func init() {
    stackCmd.PersistentFlags().StringVar(&stack_config.Libpath, "libpath", "/apex/com.android.runtime/lib64/bionic/libc.so", "full lib path")
    stackCmd.PersistentFlags().StringVar(&stack_config.Symbol, "symbol", "", "lib symbol")
    stackCmd.PersistentFlags().Uint64Var(&stack_config.Offset, "offset", 0, "lib hook offset")
    stackCmd.PersistentFlags().StringVar(&stack_config.Config, "config", "", "hook config file")
    rootCmd.AddCommand(stackCmd)
}

func stackCommandFunc(command *cobra.Command, args []string) {
    stopper := make(chan os.Signal, 1)
    signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
    ctx, cancelFun := context.WithCancel(context.TODO())

    logger := log.New(os.Stdout, "stack_", log.LstdFlags)

    gConf, err := getGlobalConf(command)
    if err != nil {
        logger.Fatal(err)
    }
    if gConf.Prepare {
        os.Exit(0)
    }

    if gConf.Uid == 0 {
        logger.Fatal("must set uid which not 0")
    }

    if gConf.loggerFile != "" {
        ex, err := os.Executable()
        if err != nil {
            logger.Fatal(err)
        }
        exec_path := path.Dir(ex)
        log_path := exec_path + "/" + gConf.loggerFile
        _, err = os.Stat(log_path)
        if err != nil {
            if os.IsNotExist(err) {
                os.Remove(log_path)
            }
        }
        f, e := os.Create(log_path)
        if e != nil {
            logger.Fatal(e)
            os.Exit(1)
        }
        if gConf.Quiet {
            // 直接设置 则不会输出到终端
            logger.SetOutput(f)
        } else {
            // 这样可以同时输出到终端
            mw := io.MultiWriter(os.Stdout, f)
            logger.SetOutput(mw)
        }
    }

    // 预设stack命令下全部的模块名
    modNames := []string{module.MODULE_NAME_STACK}

    var runMods uint8
    var runModules = make(map[string]module.IModule)
    var wg sync.WaitGroup

    for _, modName := range modNames {
        mod := module.GetModuleByName(modName)
        if mod == nil {
            logger.Printf("cant found module: %s", modName)
            break
        }

        var conf config.IConfig
        switch mod.Name() {
        case module.MODULE_NAME_STACK:
            conf = stack_config
        default:
        }

        if conf == nil {
            logger.Printf("cant found module %s config info.", mod.Name())
            break
        }

        conf.SetUid(gConf.Uid)
        conf.SetDebug(gConf.Debug)
        conf.SetUnwindStack(gConf.UnwindStack)
        conf.SetShowRegs(gConf.ShowRegs)

        err = conf.Check()

        if err != nil {
            logger.Printf("%s\tmodule initialization failed. [skip it]. error:%+v", mod.Name(), err)
            continue
        }

        logger.Printf("%s\tmodule initialization", mod.Name())

        // 初始化单个eBPF模块
        err = mod.Init(ctx, logger, conf)
        if err != nil {
            logger.Printf("%s\tmodule initialization failed, [skip it]. error:%+v", mod.Name(), err)
            continue
        }
        // 执行模块
        err = mod.Run()
        if err != nil {
            logger.Printf("%s\tmodule run failed, [skip it]. error:%+v", mod.Name(), err)
            continue
        }
        runModules[mod.Name()] = mod
        logger.Printf("%s\tmodule started successfully", mod.Name())
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
        err = mod.Close()
        wg.Done()
        if err != nil {
            logger.Fatalf("%s\tmodule close failed. error:%+v", mod.Name(), err)
        }
    }

    wg.Wait()
    os.Exit(0)
}
