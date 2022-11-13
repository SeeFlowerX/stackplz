/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
    "bufio"
    "errors"
    "fmt"
    "io/ioutil"
    "os"
    "os/exec"
    "path"
    "stackplz/assets"
    "stackplz/user/config"
    "strconv"
    "strings"

    "github.com/spf13/cobra"
)

var global_config = config.NewGlobalConfig()
var target_config = config.NewTargetConfig()

var rootCmd = &cobra.Command{
    Use:               "stackplz",
    Short:             "打印堆栈信息，目前仅支持4.14内核，出现崩溃请升级系统版本",
    Long:              "基于eBPF的堆栈追踪工具，指定目标程序的uid、库文件路径和符号即可\n\t./stackplz stack --uid 10235 --unwindstack --symbol open",
    PersistentPreRunE: persistentPreRunEFunc,
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
    global_config.ExecPath = path.Dir(exec_path)
    _, err = os.Stat(global_config.ExecPath + "/" + "preload_libs")
    var has_restore bool = false
    if err != nil {
        if os.IsNotExist(err) {
            // 路径不存在就自动释放
            err = assets.RestoreAssets(global_config.ExecPath, "preload_libs")
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
            err = assets.RestoreAssets(global_config.ExecPath, "preload_libs")
            if err != nil {
                return fmt.Errorf("RestoreAssets preload_libs failed, %v", err)
            }
        }
        fmt.Println("RestoreAssets preload_libs success")
        os.Exit(0)
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
    cobra.EnablePrefixMatching = true
    rootCmd.PersistentFlags().BoolVarP(&global_config.Prepare, "prepare", "", false, "prepare libs")
    rootCmd.PersistentFlags().StringVarP(&global_config.Name, "name", "n", "", "target package name")
    rootCmd.PersistentFlags().Uint64VarP(&global_config.Uid, "uid", "u", 0, "if uid is 0 then we target all users")
    rootCmd.PersistentFlags().BoolVarP(&global_config.Debug, "debug", "d", false, "enable debug logging")
    rootCmd.PersistentFlags().StringVarP(&global_config.LoggerFile, "out", "o", "", "-o save the packets to file")
    rootCmd.PersistentFlags().BoolVarP(&global_config.Quiet, "quiet", "", false, "use with --log-file, wont logging to terminal when used")
}
