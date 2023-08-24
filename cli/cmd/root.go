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
    "stackplz/user/event"
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

    mconfig.Parse_Idlist("UidWhitelist", gconfig.Uid)
    mconfig.Parse_Idlist("UidBlacklist", gconfig.NoUid)
    mconfig.Parse_Idlist("PidWhitelist", gconfig.Pid)
    mconfig.Parse_Idlist("PidBlacklist", gconfig.NoPid)
    mconfig.Parse_Idlist("TidWhitelist", gconfig.Tid)
    mconfig.Parse_Idlist("TidBlacklist", gconfig.NoTid)
    mconfig.SetTNamesBlacklist(gconfig.TNamesBlacklist)
    mconfig.SetTNamesWhitelist(gconfig.TNamesWhitelist)

    // 解析包名取 uid 如果是 System APP 则取 pid
    pkg_names := strings.Split(gconfig.Name, ",")
    for _, pkg_name := range pkg_names {
        err = parseByPackage(pkg_name)
        if err != nil {
            return err
        }
    }
    // 去重

    // 注意 对于系统APP 要取 pid 后面补上

    mconfig.TraceIsolated = gconfig.TraceIsolated
    mconfig.HideRoot = gconfig.HideRoot
    if gconfig.UprobeSignal != "" {
        signal, err := util.ParseSignal(gconfig.UprobeSignal)
        if err != nil {
            return err
        }
        mconfig.UprobeSignal = signal
    }
    mconfig.Buffer = gconfig.Buffer
    var brk_base uint64 = 0x0
    if gconfig.BrkLib != "" {
        if gconfig.Pid == "" {
            return errors.New("plz set pid when use breakpoint")
        }
        value, err := strconv.ParseUint(gconfig.Pid, 10, 32)
        if err != nil {
            return err
        }
        lib_info, err := event.FindLibInMaps(uint32(value), gconfig.BrkLib)
        if err != nil {
            return err
        }
        brk_base = lib_info.BaseAddr
    }

    if gconfig.BrkAddr != "" && strings.HasPrefix(gconfig.BrkAddr, "0x") {
        infos := strings.Split(gconfig.BrkAddr, ":")
        if len(infos) > 2 {
            return errors.New(fmt.Sprintf("parse for %s failed, format invaild", gconfig.BrkAddr))
        }
        if len(infos) == 2 {
            if infos[1] == "r" {
                mconfig.BrkType = util.HW_BREAKPOINT_R
            } else if infos[1] == "w" {
                mconfig.BrkType = util.HW_BREAKPOINT_W
            } else if infos[1] == "x" {
                mconfig.BrkType = util.HW_BREAKPOINT_X
            } else if infos[1] == "rw" {
                mconfig.BrkType = util.HW_BREAKPOINT_RW
            } else {
                return errors.New(fmt.Sprintf("parse BrkType for %s failed", infos[1]))
            }
        } else {
            mconfig.BrkType = util.HW_BREAKPOINT_X
        }
        addr, err := strconv.ParseUint(strings.TrimPrefix(infos[0], "0x"), 16, 64)
        if err != nil {
            return errors.New(fmt.Sprintf("parse for %s failed, err:%v", gconfig.BrkAddr, err))
        }
        mconfig.BrkAddr = brk_base + addr
    }

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

    mconfig.InitSyscallConfig()
    mconfig.InitStackUprobeConfig()

    mconfig.StackUprobeConf.LibPath, err = util.FindLib(gconfig.Library, gconfig.LibraryDirs)
    if err != nil {
        logger.Fatal(err)
        os.Exit(1)
    }

    // 处理 syscall 的命令
    mconfig.SysCallConf.Parse_SysWhitelist(gconfig.SysCall)
    mconfig.SysCallConf.Parse_SysBlacklist(gconfig.NoSysCall)

    if len(gconfig.HookPoint) != 0 {
        if len(gconfig.HookPoint) > 8 {
            logger.Fatal("max uprobe hook point count is 8")
        }
        err = mconfig.StackUprobeConf.ParseConfig(gconfig.HookPoint)
        if err != nil {
            return err
        }
    } else if mconfig.BrkAddr != 0 {
        logger.Printf("set breakpoint addr:0x%x", mconfig.BrkAddr)
    } else {
        logger.Fatal("hook nothing, plz set -w/--point or -s/--syscall")
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

    var modNames []string
    if mconfig.BrkAddr != 0 {
        modNames = []string{module.MODULE_NAME_BRK}
    } else {
        modNames = []string{module.MODULE_NAME_PERF, module.MODULE_NAME_STACK}
    }
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

func parseByUid(uid string) error {
    // pm list package --uid 10245

    if uid == "1000" || uid == "2000" || uid == "0" {
        gconfig.Is32Bit = false
        return nil
    }

    lines, err := runCommand("pm", "list", "package", "--uid", uid)
    if err != nil {
        return err
    }

    if lines == "" {
        return fmt.Errorf("can not find package by uid=%s", uid)
    }
    parts := strings.SplitN(lines, " ", 2)
    if len(parts) != 2 {
        return fmt.Errorf("get package name by uid=%s failed, sep => <=", uid)
    }
    name := strings.SplitN(parts[0], ":", 2)
    if len(name) != 2 {
        return fmt.Errorf("get package name by uid=%s failed, sep =>:<=", uid)
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
    if uid >= 10000 && uid <= 19999 {
        return parseByUid(fmt.Sprintf("%d", uid))
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
                value, err := strconv.ParseUint(value, 10, 32)
                if err != nil {
                    panic(err)
                }
                // 考虑到是基于 特定模式 的过滤 对于单个系统APP进程 这里赋值了也没有影响
                // 不过后续的逻辑发生变更 要注意这里什么情况下才赋值
                mconfig.UidWhitelist = append(mconfig.UidWhitelist, uint32(value))
            case "legacyNativeLibraryDir":
                // 考虑到后面会通过其他方式增加搜索路径 所以是数组
                gconfig.LibraryDirs = append(gconfig.LibraryDirs, value+"/"+"arm64")
            case "dataDir":
                gconfig.DataDir = value
            case "primaryCpuAbi":
                // 只支持 arm64 否则直接返回错误
                if value != "" && value != "arm64-v8a" {
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
    // 考虑到外部库更新 每个版本首次运行前 都应该执行一次
    rootCmd.PersistentFlags().BoolVar(&gconfig.Prepare, "prepare", false, "prepare libs")
    // 过滤设定
    rootCmd.PersistentFlags().StringVarP(&gconfig.Name, "name", "n", "", "must set uid or package name")
    rootCmd.PersistentFlags().StringVarP(&gconfig.Uid, "uid", "u", "", "uid white list")
    rootCmd.PersistentFlags().StringVarP(&gconfig.Pid, "pid", "p", "", "pid white list")
    rootCmd.PersistentFlags().StringVarP(&gconfig.Tid, "tid", "t", "", "tid white list")
    rootCmd.PersistentFlags().StringVar(&gconfig.NoUid, "no-uid", "", "uid black list")
    rootCmd.PersistentFlags().StringVar(&gconfig.NoPid, "no-pid", "", "pid black list")
    rootCmd.PersistentFlags().StringVar(&gconfig.NoTid, "no-tid", "", "tid black list")
    rootCmd.PersistentFlags().StringVar(&gconfig.TNamesWhitelist, "tnames", "", "thread name white list, max 20")
    rootCmd.PersistentFlags().StringVar(&gconfig.TNamesBlacklist, "no-tnames", "", "thread name black list, max 20")
    rootCmd.PersistentFlags().BoolVar(&gconfig.TraceIsolated, "iso", false, "watch isolated process")
    rootCmd.PersistentFlags().BoolVar(&gconfig.HideRoot, "hide-root", false, "hide some root feature")
    rootCmd.PersistentFlags().StringVar(&gconfig.UprobeSignal, "kill", "", "send signal when hit uprobe hook, e.g. SIGSTOP/SIGABRT/SIGTRAP/...")
    // 硬件断点设定
    rootCmd.PersistentFlags().StringVarP(&gconfig.BrkAddr, "brk", "", "", "set hardware breakpoint address")
    rootCmd.PersistentFlags().StringVarP(&gconfig.BrkLib, "brk-lib", "", "", "as library base address")
    // 缓冲区大小设定 单位M
    rootCmd.PersistentFlags().Uint32VarP(&gconfig.Buffer, "buffer", "b", 8, "perf cache buffer size, default 8M")
    // 堆栈输出设定
    rootCmd.PersistentFlags().BoolVar(&gconfig.UnwindStack, "stack", false, "enable unwindstack")
    rootCmd.PersistentFlags().Uint32VarP(&gconfig.StackSize, "stack-size", "", 8192, "stack dump size, default 8192 bytes, max 65528 bytes")
    rootCmd.PersistentFlags().BoolVar(&gconfig.ShowRegs, "regs", false, "show regs")
    rootCmd.PersistentFlags().BoolVar(&gconfig.GetOff, "getoff", false, "try get pc and lr offset")
    // 日志设定
    rootCmd.PersistentFlags().BoolVarP(&gconfig.Debug, "debug", "d", false, "enable debug logging")
    rootCmd.PersistentFlags().BoolVarP(&gconfig.Quiet, "quiet", "q", false, "wont logging to terminal when used")
    rootCmd.PersistentFlags().BoolVarP(&gconfig.Color, "color", "c", false, "enable color for log file")
    rootCmd.PersistentFlags().StringVarP(&gconfig.LogFile, "out", "o", "stackplz_tmp.log", "save the log to file")
    // 常规ELF库hook设定
    rootCmd.PersistentFlags().StringVarP(&gconfig.Library, "lib", "l", "/apex/com.android.runtime/lib64/bionic/libc.so", "full lib path")
    rootCmd.PersistentFlags().StringArrayVarP(&gconfig.HookPoint, "point", "w", []string{}, "hook point config, e.g. strstr+0x0[str,str] write[int,buf:128,int]")
    rootCmd.PersistentFlags().StringVar(&gconfig.RegName, "reg", "", "get the offset of reg")
    rootCmd.PersistentFlags().BoolVarP(&gconfig.DumpHex, "dumphex", "", false, "dump buffer as hex")
    rootCmd.PersistentFlags().BoolVarP(&gconfig.NoCheck, "nocheck", "", false, "disable check for bpf")
    rootCmd.PersistentFlags().BoolVarP(&gconfig.Btf, "btf", "", false, "declare BTF enabled")
    // syscall hook
    rootCmd.PersistentFlags().StringVarP(&gconfig.SysCall, "syscall", "s", "", "filter syscalls")
    rootCmd.PersistentFlags().StringVar(&gconfig.NoSysCall, "no-syscall", "", "syscall black list, max 20")
}
