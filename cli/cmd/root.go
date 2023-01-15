/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
    "bufio"
    "context"
    "errors"
    "fmt"
    "io"
    "io/ioutil"
    "log"
    "os"
    "os/exec"
    "os/signal"
    "path"
    "stackplz/assets"
    "stackplz/user/config"
    "stackplz/user/module"
    "strconv"
    "strings"
    "sync"
    "syscall"

    "github.com/spf13/cobra"
)

var exec_path = "/data/local/tmp"
var global_config = config.NewGlobalConfig()
var target_config = config.NewTargetConfig()

var rootCmd = &cobra.Command{
    Use:               "stackplz",
    Short:             "打印堆栈信息，目前仅支持4.14内核，出现崩溃请升级系统版本",
    Long:              "基于eBPF的堆栈追踪工具，指定目标程序的uid、库文件路径和符号即可\n\t./stackplz stack --uid 10235 --stack --symbol open",
    PersistentPreRunE: persistentPreRunEFunc,
    Run:               runFunc,
}

// cobra.Command 中几个函数执行的顺序
// PersistentPreRun
// PreRun
// Run
// PostRun
// PersistentPostRun

func persistentPreRunEFunc(command *cobra.Command, args []string) error {
    // 在执行子命令的时候 上级命令的 PersistentPreRun/PersistentPreRunE 会先执行
    // 优先通过包名指定要hook的目标 在执行子命令之前先通过包名得到uid

    // 第一步先释放用于获取堆栈信息的外部库
    exec_path, err := os.Executable()
    if err != nil {
        return fmt.Errorf("please build as executable binary, %v", err)
    }
    // 获取一次 后面用得到 免去重复获取
    exec_path = path.Dir(exec_path)
    _, err = os.Stat(exec_path + "/" + "preload_libs")
    var has_restore bool = false
    if err != nil {
        if os.IsNotExist(err) {
            // 路径不存在就自动释放
            err = assets.RestoreAssets(exec_path, "preload_libs")
            if err != nil {
                return fmt.Errorf("RestoreAssets preload_libs failed, %v", err)
            }
            has_restore = true
        } else {
            // 未知异常 比如权限问题 那么直接结束
            return err
        }
    }
    if global_config.Prepare {
        // 认为是需要重新释放一次
        if !has_restore {
            err = assets.RestoreAssets(exec_path, "preload_libs")
            if err != nil {
                return fmt.Errorf("RestoreAssets preload_libs failed, %v", err)
            }
        }
        fmt.Println("RestoreAssets preload_libs success")
        os.Exit(0)
    }
    if global_config.Pid > 0 {
        target_config.Pid = global_config.Pid
    }

    target_config.TidsBlacklistMask = 0
    if global_config.TidsBlacklist != "" {
        tids := strings.Split(global_config.TidsBlacklist, ",")
        if len(tids) > 20 {
            return fmt.Errorf("max tid blacklist count is 20, provided count:%d", len(tids))
        }
        for i, v := range tids {
            value, _ := strconv.ParseUint(v, 10, 32)
            target_config.TidsBlacklist[i] = uint32(value)
            target_config.TidsBlacklistMask |= (1 << i)
        }
    }

    // 第二步 通过包名获取uid和库路径 先通过pm命令获取安装位置
    if global_config.Name != "" {
        return parseByPackage(global_config.Name)
    } else if global_config.Uid != 0 {
        return parseByUid(global_config.Uid)
    } else {
        return errors.New("please set --uid or --name")
    }
}

func runFunc(command *cobra.Command, args []string) {
    stopper := make(chan os.Signal, 1)
    signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
    ctx, cancelFun := context.WithCancel(context.TODO())

    // 首先根据全局设定设置日志输出
    logger := log.New(os.Stdout, "", log.Lmicroseconds)
    if global_config.LogFile != "" {
        log_path := exec_path + "/" + global_config.LogFile
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

    module_config, err := toModuleConfig(global_config)
    if err != nil {
        logger.Printf("toModuleConfig failed, %v", err)
        os.Exit(1)
    }

    var runMods uint8
    var wg sync.WaitGroup

    mod := &module.Module{}

    mod.Init(ctx, logger, module_config)
    err = mod.Run()
    if err != nil {
        logger.Printf("%s\tmodule Run failed, [skip it]. error:%+v", mod.Name(), err)
        os.Exit(1)
    }
    if global_config.Debug {
        logger.Printf("%s\tmodule started successfully", mod.Name())
    }
    wg.Add(1)
    runMods++

    if runMods > 0 {
        logger.Printf("start %d modules", runMods)
        <-stopper
    } else {
        logger.Println("No runnable modules, Exit(1)")
        os.Exit(1)
    }
    cancelFun()

    err = mod.Close()
    logger.Println("mod Close")
    wg.Done()
    if err != nil {
        logger.Fatalf("%s:module close failed. error:%+v", mod.Name(), err)
    }

    wg.Wait()
    os.Exit(0)
}

func toModuleConfig(global_config *config.GlobalConfig) (*config.ModuleConfig, error) {
    // 转换命令行的选项 并且进行检查
    module_config := config.NewModuleConfig()

    return module_config, nil
}

func parseByUid(uid uint64) error {
    // pm list package --uid 10245
    cmd := exec.Command("pm", "list", "package", "--uid", strconv.FormatUint(uid, 10))

    //创建获取命令输出管道
    stdout, err := cmd.StdoutPipe()
    if err != nil {
        return err
    }

    //执行命令
    if err := cmd.Start(); err != nil {
        return err
    }

    //读取所有输出
    bytes, err := ioutil.ReadAll(stdout)
    if err != nil {
        return err
    }

    if err := cmd.Wait(); err != nil {
        return err
    }
    line := strings.TrimSpace(string(bytes))
    if line == "" {
        return fmt.Errorf("can not find package by uid=%d", uid)
    }
    parts := strings.SplitN(line, " ", 2)
    if len(parts) != 2 {
        return fmt.Errorf("get package name by uid=%d failed, sep => <=", uid)
    }
    name := strings.SplitN(parts[0], ":", 2)
    if len(name) != 2 {
        return fmt.Errorf("get package name by uid=%d failed, sep =>:<=", uid)
    }
    return parseByPackage(name[1])
}

func parseByPackage(name string) error {
    target_config.Name = name
    global_config.Name = name
    cmd := exec.Command("dumpsys", "package", name)

    // 创建获取命令输出管道
    stdout, err := cmd.StdoutPipe()
    if err != nil {
        return err
    }

    // 执行命令
    if err := cmd.Start(); err != nil {
        return err
    }

    // 使用带缓冲的读取器
    outputBuf := bufio.NewReader(stdout)

    for {
        // 按行读
        output, _, err := outputBuf.ReadLine()
        if err != nil {
            // 判断是否到文件的结尾了否则出错
            if err.Error() != "EOF" {
                return err
            }
            break
        }
        line := strings.Trim(string(output), " ")
        parts := strings.SplitN(line, "=", 2)
        if len(parts) == 2 {
            key := parts[0]
            value := parts[1]
            switch key {
            case "userId":
                target_config.Uid, _ = strconv.ParseUint(value, 10, 64)
                // 只指定了包名的时候 global_config.Uid 是 0 需要修正
                global_config.Uid = target_config.Uid
            case "legacyNativeLibraryDir":
                // 考虑到后面会通过其他方式增加搜索路径 所以是数组
                target_config.LibraryDirs = append(target_config.LibraryDirs, value)
            case "dataDir":
                target_config.DataDir = value
            case "primaryCpuAbi":
                // 只支持 arm64 否则直接返回错误
                if value == "arm64-v8a" {
                    if len(target_config.LibraryDirs) != 1 {
                        // 一般是不会进入这个分支 万一呢
                        return fmt.Errorf("can not find legacyNativeLibraryDir, cmd:%s", strings.Join(cmd.Args, " "))
                    }
                    target_config.LibraryDirs[0] = target_config.LibraryDirs[0] + "/" + "arm64"
                } else {
                    return fmt.Errorf("not support package=%s primaryCpuAbi=%s", name, value)
                }
            }
        }
    }
    // wait 方法会一直阻塞到其所属的命令完全运行结束为止
    if err := cmd.Wait(); err != nil {
        return err
    }
    return nil
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
    // 异常时不显示帮助信息 只提示异常 因为帮助信息占据的版面太多
    rootCmd.SilenceUsage = true
    rootCmd.CompletionOptions.DisableDefaultCmd = true
    err := rootCmd.Execute()
    if err != nil {
        os.Exit(1)
    }
}

func init() {
    cobra.EnablePrefixMatching = false
    // 首次运行
    rootCmd.PersistentFlags().BoolVar(&global_config.Prepare, "prepare", false, "prepare libs")
    // 过滤设定
    rootCmd.PersistentFlags().StringVarP(&global_config.Name, "name", "n", "", "must set uid or package name")
    rootCmd.PersistentFlags().Uint64VarP(&global_config.Uid, "uid", "u", 0, "must set uid or package name")
    rootCmd.PersistentFlags().Uint64VarP(&global_config.Pid, "pid", "p", 0, "add pid to filter")
    // 堆栈输出设定
    rootCmd.PersistentFlags().BoolVar(&global_config.UnwindStack, "stack", false, "enable unwindstack")
    rootCmd.PersistentFlags().BoolVar(&global_config.ShowRegs, "regs", false, "show regs")
    rootCmd.PersistentFlags().BoolVar(&global_config.GetLR, "getlr", false, "try get lr info")
    rootCmd.PersistentFlags().BoolVar(&global_config.GetPC, "getpc", false, "try get pc info")
    // 黑白名单设定
    rootCmd.PersistentFlags().StringVarP(&global_config.TidsBlacklist, "no-tids", "nt", "", "tid black list, max 20")
    // 日志设定
    rootCmd.PersistentFlags().BoolVarP(&global_config.Debug, "debug", "d", false, "enable debug logging")
    rootCmd.PersistentFlags().BoolVarP(&global_config.Quiet, "quiet", "q", false, "wont logging to terminal when used")
    rootCmd.PersistentFlags().StringVarP(&global_config.LogFile, "out", "o", "stackplz_tmp.log", "save the log to file")
    // 常规ELF库hook设定
    rootCmd.PersistentFlags().StringVarP(&global_config.Library, "library", "lib", "/apex/com.android.runtime/lib64/bionic/libc.so", "full lib path")
    rootCmd.PersistentFlags().StringVarP(&global_config.Symbol, "symbol", "sym", "", "lib symbol")
    rootCmd.PersistentFlags().Uint64VarP(&global_config.Offset, "offset", "off", 0, "lib hook offset")
    rootCmd.PersistentFlags().StringVar(&global_config.RegName, "reg", "", "get the offset of reg")
    // syscall hook
    rootCmd.PersistentFlags().StringVar(&global_config.SysCall, "syscall", "", "filter syscalls")
    // 批量hook先放一边
    // rootCmd.PersistentFlags().StringVar(&global_config.Config, "config", "", "hook config file")
}
