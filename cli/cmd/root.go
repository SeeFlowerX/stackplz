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
    "stackplz/user/util"
    "strconv"
    "strings"
    "sync"
    "syscall"

    "github.com/spf13/cobra"
)

var Logger *log.Logger

func NewLogger(log_path string) *log.Logger {
    if Logger != nil {
        return Logger
    }
    // 首先根据全局设定设置日志输出
    Logger = log.New(os.Stdout, "", 0)
    if gconfig.LogFile != "" {
        _, err := os.Stat(log_path)
        if err != nil {
            if os.IsNotExist(err) {
                os.Remove(log_path)
            }
        }
        f, err := os.Create(log_path)
        if err != nil {
            Logger.Fatal(err)
            os.Exit(1)
        }
        if gconfig.Quiet {
            // 直接设置 则不会输出到终端
            Logger.SetOutput(f)
        } else {
            // 这样可以同时输出到终端
            mw := io.MultiWriter(os.Stdout, f)
            Logger.SetOutput(mw)
        }
    }

    return Logger
}

var gconfig = config.NewGlobalConfig()
var mconfig = config.NewModuleConfig()

var rootCmd = &cobra.Command{
    Use:               "stackplz",
    Short:             "打印堆栈信息，目前仅支持5.10+内核，出现崩溃请升级系统版本",
    Long:              "基于eBPF的堆栈追踪工具，指定目标程序的uid、库文件路径和符号即可\n\t./stackplz --name com.sfx.ebpf --syscall openat -o tmp.log --debug",
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

    var err error

    // 首先根据全局设定设置日志输出
    dir, _ := os.Getwd()
    log_path := dir + "/" + gconfig.LogFile
    if gconfig.LogFile != "" {
        _, err := os.Stat(log_path)
        if err != nil {
            if os.IsNotExist(err) {
                os.Remove(log_path)
            } else {
                fmt.Printf("stat %s failed, error:%v", log_path, err)
                os.Exit(1)
            }
        } else {
            os.Remove(log_path)
        }
    }

    // 在 init 之后各个选项的 flag 还没有初始化 到这里才初始化 所以在这里最先设置好 logger
    logger := NewLogger(log_path)
    mconfig.SetLogger(logger)
    if !gconfig.NoCheck {
        // 先检查必要的配置
        err = util.CheckKernelConfig()
        if err != nil {
            logger.Fatalf("CheckKernelConfig failed, error:%v", err)
        }
    }
    if gconfig.Btf {
        mconfig.ExternalBTF = ""
    } else {
        if !util.HasEnableBTF {
            // 检查平台 判断是不是开发板
            mconfig.ExternalBTF = findBTFAssets()
        } else {
            mconfig.ExternalBTF = ""
        }
    }
    // 检查符号情况 用于判断部分选项是否能启用
    has_bpf_probe_read_user, err := findKallsymsSymbol("bpf_probe_read_user")
    if err != nil {
        logger.Printf("bpf_probe_read_user err:%v", err)
        return err
    }
    if !has_bpf_probe_read_user {
        logger.Fatalf("not support for this machine, has no bpf_probe_read_user")
    }

    // 第一步先释放用于获取堆栈信息的外部库
    exec_path, err := os.Executable()
    if err != nil {
        return fmt.Errorf("please build as executable binary, %v", err)
    }
    if gconfig.Debug {
        logger.Printf("Executable:%s", exec_path)
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
    if gconfig.Prepare {
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

    // 第二步 通过包名获取uid和库路径 先通过pm命令获取安装位置
    // 支持设置单独的pid，但是要排除程序本身的pid
    if gconfig.Name != "" {
        err = parseByPackage(gconfig.Name)
        if err != nil {
            return err
        }
        if gconfig.Uid == config.MAGIC_UID {
            logger.Fatalf("get uid by package name:%s failed", gconfig.Name)
        }
        // 如果说是系统APP 那么这里解析出来的uid是2000 应该用 PID_MODE
        if gconfig.Uid == 2000 {
            // 这里现在还有一种情况没有继续适配
            // 如果系统APP这个时候还没有运行 那么实际上没有pid...
            mconfig.FilterMode = util.PID_MODE
            panic("watch system app by --name not supported yet, plz use --pid")
        } else {
            mconfig.FilterMode = util.UID_MODE
        }
    } else if gconfig.Uid != config.MAGIC_UID {
        err = parseByUid(gconfig.Uid)
        if err != nil {
            return err
        }
        mconfig.FilterMode = util.UID_MODE
    } else if gconfig.Pid != 0 {
        if gconfig.Tid != config.MAGIC_TID {
            mconfig.FilterMode = util.PID_TID_MODE
            logger.Printf("watch for pid:%d + tid:%d", gconfig.Pid, gconfig.Tid)
        } else {
            if gconfig.Pid == config.MAGIC_PID {
                logger.Fatalf("please set one of them --pid/--uid/--name")
            }
            mconfig.FilterMode = util.PID_MODE
            logger.Printf("watch for pid:%d", gconfig.Pid)
        }
        err = parseByPid(gconfig.Pid)
        if err != nil {
            return err
        }
    } else {
        return errors.New("please set --uid/--name/--pid/--pid + --tid")
    }

    // 转换命令行的选项 并且进行检查
    mconfig.Uid = gconfig.Uid
    mconfig.Pid = gconfig.Pid
    mconfig.Tid = gconfig.Tid
    mconfig.Buffer = gconfig.Buffer
    mconfig.UnwindStack = gconfig.UnwindStack
    if gconfig.StackSize&7 != 0 {
        return errors.New(fmt.Sprintf("dump stack size %d is not 8-byte aligned.", gconfig.StackSize))
    }
    mconfig.StackSize = gconfig.StackSize
    mconfig.ShowRegs = gconfig.ShowRegs
    mconfig.GetOff = gconfig.GetOff
    mconfig.Debug = gconfig.Debug
    mconfig.Is32Bit = gconfig.Is32Bit
    mconfig.Color = gconfig.Color
    mconfig.DumpHex = gconfig.DumpHex
    err = mconfig.SetTidsBlacklist(gconfig.TidsBlacklist)
    if err != nil {
        return err
    }
    err = mconfig.SetPidsBlacklist(gconfig.PidsBlacklist)
    if err != nil {
        return err
    }
    err = mconfig.SetTNamesBlacklist(gconfig.TNamesBlacklist)
    if err != nil {
        return err
    }
    err = mconfig.SetTNamesWhitelist(gconfig.TNamesWhitelist)
    if err != nil {
        return err
    }
    // 这里暂时是针对 stack 命令 后续整合 syscall 要进行区分
    mconfig.StackUprobeConf.LibPath, err = util.FindLib(gconfig.Library, gconfig.LibraryDirs)
    if err != nil {
        logger.Fatal(err)
        os.Exit(1)
    }

    // 处理 syscall 的命令
    if gconfig.SysCall != "" {
        // 先把 syscall 的配置加载起来
        err = mconfig.SysCallConf.SetUp(gconfig.Is32Bit)
        if err != nil {
            return err
        }
        // 特别的 设置为 all 表示追踪全部的系统调用
        // 后续引入按 syscall 分类追踪的选项
        err = mconfig.SysCallConf.SetSysCall(gconfig.SysCall)
        if err != nil {
            return err
        }
        if gconfig.SysCallBlacklist != "" {
            err = mconfig.SysCallConf.SetSysCallBlacklist(gconfig.SysCallBlacklist)
            if err != nil {
                return err
            }
        }
    } else if len(gconfig.HookPoint) != 0 {
        if len(gconfig.HookPoint) > 10 {
            logger.Fatal("max uprobe hook point count is 10")
        }
        err = mconfig.StackUprobeConf.ParseConfig(gconfig.HookPoint)
        if err != nil {
            return err
        }
    } else {
        logger.Fatal("hook nothing, plz set --symbol/--library + --offset")
    }

    return nil
}

func runFunc(command *cobra.Command, args []string) {
    stopper := make(chan os.Signal, 1)
    signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
    ctx, cancelFun := context.WithCancel(context.TODO())

    var runMods uint8
    var runModules = make(map[string]module.IModule)
    var wg sync.WaitGroup

    modNames := []string{module.MODULE_NAME_PERF, module.MODULE_NAME_STACK}
    for _, modName := range modNames {
        // 现在合并成只有一个模块了 所以直接通过名字获取
        mod := module.GetModuleByName(modName)

        mod.Init(ctx, Logger, mconfig)
        err := mod.Run()
        if err != nil {
            Logger.Printf("%s\tmodule Run failed, [skip it]. error:%+v", mod.Name(), err)
            os.Exit(1)
        }
        runModules[mod.Name()] = mod
        if gconfig.Debug {
            Logger.Printf("%s\tmodule started successfully", mod.Name())
        }
        wg.Add(1)
        runMods++

    }
    if runMods > 0 {
        Logger.Printf("start %d modules", runMods)
        <-stopper
    } else {
        Logger.Println("No runnable modules, Exit(1)")
        os.Exit(1)
    }
    cancelFun()

    for _, mod := range runModules {
        err := mod.Close()
        Logger.Println("mod Close")
        wg.Done()
        if err != nil {
            Logger.Fatalf("%s:module close failed. error:%+v", mod.Name(), err)
        }
    }
    wg.Wait()
    os.Exit(0)
}

func runCommand(executable string, args ...string) (string, error) {
    cmd := exec.Command(executable, args...)
    stdout, err := cmd.StdoutPipe()
    if err != nil {
        return "", err
    }
    if err := cmd.Start(); err != nil {
        return "", err
    }
    bytes, err := ioutil.ReadAll(stdout)
    if err != nil {
        return "", err
    }
    if err := cmd.Wait(); err != nil {
        return "", err
    }
    return strings.TrimSpace(string(bytes)), nil
}

func parseByUid(uid uint32) error {
    // pm list package --uid 10245

    if uid == 1000 || uid == 2000 || uid == 0 {
        gconfig.Is32Bit = false
        return nil
    }

    lines, err := runCommand("pm", "list", "package", "--uid", strconv.FormatUint(uint64(uid), 10))
    if err != nil {
        return err
    }

    if lines == "" {
        return fmt.Errorf("can not find package by uid=%d", uid)
    }
    parts := strings.SplitN(lines, " ", 2)
    if len(parts) != 2 {
        return fmt.Errorf("get package name by uid=%d failed, sep => <=", uid)
    }
    name := strings.SplitN(parts[0], ":", 2)
    if len(name) != 2 {
        return fmt.Errorf("get package name by uid=%d failed, sep =>:<=", uid)
    }
    return parseByPackage(name[1])
}

func findBTFAssets() string {
    lines, err := runCommand("uname", "-r")
    if err != nil {
        panic(fmt.Sprintf("findBTFAssets failed, can not exec uname -r, err:%v", err))
    }
    btf_file := "a12-5.10-arm64_min.btf"
    if strings.Contains(lines, "rockchip") {
        btf_file = "rock5b-5.10-arm64_min.btf"
    }
    if gconfig.Debug {
        Logger.Printf("[findBTFAssets] btf_file=%s", btf_file)
    }
    return btf_file
}

func parseByPid(pid uint32) error {

    pid_str := strconv.FormatUint(uint64(pid), 10)
    maps_path := "/proc/" + pid_str + "/maps"

    // uid=$(ps -o user= -p 22812) && id -u $uid
    // 先通过这样的命令获取到进程的 uid 判断是不是APP进程
    lines, err := runCommand("sh", "-c", fmt.Sprintf("uid=$(ps -o user= -p %s ) && id -u $uid", pid_str))
    if err != nil {
        return err
    }
    if gconfig.Debug {
        Logger.Printf("[parseByPid] get uid by pid=%d result:\n\t%s", pid, lines)
    }
    value, _ := strconv.ParseUint(lines, 10, 32)
    uid := uint32(value)
    // 这个范围内的是常规的 APP 进程
    if uid > 10000 && uid < 20000 {
        return parseByUid(uid)
    }
    // 特殊的 uid
    // root 0
    // system 1000
    // shell 2000
    if uid == 1000 {
        // 考虑到 system app 进程的 uid 都是 1000
        // 那么这种尝试通过检查 maps 的 app_process 来确定架构以及库文件路径
        lines, err = runCommand("sh", "-c", fmt.Sprintf("cat %s | grep -m1 bin/app_process", maps_path))
        if err != nil {
            return err
        }
        if gconfig.Debug {
            Logger.Printf("[parseByPid] check app_process by pid=%d result:\n\t%s", pid, lines)
        }
        if strings.HasSuffix(lines, "/app_process64") {
            gconfig.Is32Bit = false
        } else if strings.HasSuffix(lines, "/app_process") {
            gconfig.Is32Bit = true
        } else {
            return fmt.Errorf("[parseByPid] can not find detect process arch by pid=%d", pid)
        }
    }

    // 通过检查 进程 maps 中 linker 的名字确定是 32 还是 64
    // cat /proc/22812/maps | grep -m1 bin/linker
    lines, err = runCommand("sh", "-c", fmt.Sprintf("cat %s | grep -m1 bin/linker", maps_path))
    if err != nil {
        return err
    }
    if lines == "" {
        return fmt.Errorf("[parseByPid] can not find detect process arch by pid=%d", pid)
    }
    if strings.HasSuffix(lines, "/linker64") {
        gconfig.Is32Bit = false
    } else if strings.HasSuffix(lines, "/linker") {
        gconfig.Is32Bit = true
    } else {
        return fmt.Errorf("[parseByPid] can not find detect process arch by pid=%d", pid)
    }
    return nil
}

func findKallsymsSymbol(symbol string) (bool, error) {
    find := false
    content, err := ioutil.ReadFile("/proc/kallsyms")
    if err != nil {
        return find, fmt.Errorf("Error when opening file:%v", err)
    }
    lines := string(content)
    for _, line := range strings.Split(lines, "\n") {
        parts := strings.SplitN(line, " ", 3)
        if len(parts) != 3 {
            continue
        }
        if parts[2] == symbol {
            find = true
            break
        }
    }
    return find, nil
}

func parseByPackage(name string) error {
    // 先设置默认值
    gconfig.Is32Bit = true
    gconfig.Name = name
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
                value, _ := strconv.ParseUint(value, 10, 32)
                // 考虑到是基于 特定模式 的过滤 对于单个系统APP进程 这里赋值了也没有影响
                // 不过后续的逻辑发生变更 要注意这里什么情况下才赋值
                gconfig.Uid = uint32(value)
            case "legacyNativeLibraryDir":
                // 考虑到后面会通过其他方式增加搜索路径 所以是数组
                gconfig.LibraryDirs = append(gconfig.LibraryDirs, value)
            case "dataDir":
                gconfig.DataDir = value
            case "primaryCpuAbi":
                // 只支持 arm64 否则直接返回错误
                // 不过对于syscall则是支持 32 位的 后面优化逻辑
                if value == "arm64-v8a" {
                    gconfig.Is32Bit = false
                    if len(gconfig.LibraryDirs) != 1 {
                        // 一般是不会进入这个分支 万一呢
                        return fmt.Errorf("can not find legacyNativeLibraryDir, cmd:%s", strings.Join(cmd.Args, " "))
                    }
                    gconfig.LibraryDirs[0] = gconfig.LibraryDirs[0] + "/" + "arm64"
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
    if gconfig.Uid == 0 {
        return fmt.Errorf("parseByPackage failed, uid is 0, package name:%s", name)
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
    // 考虑到外部库更新 每个版本首次运行前 都应该执行一次
    rootCmd.PersistentFlags().BoolVar(&gconfig.Prepare, "prepare", false, "prepare libs")
    // 过滤设定
    rootCmd.PersistentFlags().StringVarP(&gconfig.Name, "name", "n", "", "must set uid or package name")
    rootCmd.PersistentFlags().Uint32VarP(&gconfig.Uid, "uid", "u", config.MAGIC_UID, "must set uid or package name")
    rootCmd.PersistentFlags().Uint32VarP(&gconfig.Pid, "pid", "p", config.MAGIC_PID, "add pid to filter")
    rootCmd.PersistentFlags().Uint32VarP(&gconfig.Tid, "tid", "t", config.MAGIC_TID, "add tid to filter")
    rootCmd.PersistentFlags().StringVar(&gconfig.TNamesWhitelist, "tnames", "", "thread name white list, max 20")
    // 缓冲区大小设定 单位M
    rootCmd.PersistentFlags().Uint32VarP(&gconfig.Buffer, "buffer", "b", 8, "perf cache buffer size, default 8M")
    // 堆栈输出设定
    rootCmd.PersistentFlags().BoolVar(&gconfig.UnwindStack, "stack", false, "enable unwindstack")
    rootCmd.PersistentFlags().Uint32VarP(&gconfig.StackSize, "stack-size", "", 8192, "stack dump size, default 8192 bytes, max 65528 bytes")
    rootCmd.PersistentFlags().BoolVar(&gconfig.ShowRegs, "regs", false, "show regs")
    rootCmd.PersistentFlags().BoolVar(&gconfig.GetOff, "getoff", false, "try get pc and lr offset")
    // 黑白名单设定
    rootCmd.PersistentFlags().StringVar(&gconfig.TidsBlacklist, "no-tids", "", "tid black list, max 20")
    rootCmd.PersistentFlags().StringVar(&gconfig.PidsBlacklist, "no-pids", "", "pid black list, max 20")
    rootCmd.PersistentFlags().StringVar(&gconfig.TNamesBlacklist, "no-tnames", "", "thread name black list, max 20")
    // 日志设定
    rootCmd.PersistentFlags().BoolVarP(&gconfig.Debug, "debug", "d", false, "enable debug logging")
    rootCmd.PersistentFlags().BoolVarP(&gconfig.Quiet, "quiet", "q", false, "wont logging to terminal when used")
    rootCmd.PersistentFlags().BoolVarP(&gconfig.Color, "color", "c", false, "enable color for log file")
    rootCmd.PersistentFlags().StringVarP(&gconfig.LogFile, "out", "o", "stackplz_tmp.log", "save the log to file")
    // 常规ELF库hook设定
    rootCmd.PersistentFlags().StringVarP(&gconfig.Library, "library", "l", "/apex/com.android.runtime/lib64/bionic/libc.so", "full lib path")
    rootCmd.PersistentFlags().StringArrayVarP(&gconfig.HookPoint, "point", "w", []string{}, "hook point config, e.g. strstr+0x0[str,str] write[int,hex:128,int]")
    rootCmd.PersistentFlags().StringVar(&gconfig.RegName, "reg", "", "get the offset of reg")
    rootCmd.PersistentFlags().BoolVarP(&gconfig.DumpHex, "dumphex", "", false, "dump buffer as hex")
    rootCmd.PersistentFlags().BoolVarP(&gconfig.NoCheck, "nocheck", "", false, "disable check for bpf")
    rootCmd.PersistentFlags().BoolVarP(&gconfig.Btf, "btf", "", false, "declare BTF enabled")
    // syscall hook
    rootCmd.PersistentFlags().StringVarP(&gconfig.SysCall, "syscall", "s", "", "filter syscalls")
    rootCmd.PersistentFlags().StringVar(&gconfig.SysCallBlacklist, "no-syscall", "", "syscall black list, max 20")
}
