/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
    "edemo/assets"
    "fmt"
    "os"
    "path"

    "github.com/spf13/cobra"
)

const (
    defaultPid uint64 = 0
    defaultUid uint64 = 0
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
    Use:   "stackplz",
    Short: "打印堆栈信息，目前仅支持4.14内核，出现崩溃请升级系统版本",
    Long:  "基于eBPF的堆栈追踪工具，指定目标程序的uid、库文件路径和符号即可\n\t./stackplz stack --uid 10235 --unwindstack --symbol open",
    // Uncomment the following line if your bare application
    // has an action associated with it:
    PersistentPreRun: preloadFunc,
}

func preloadFunc(command *cobra.Command, args []string) {
    prepare, err := command.Flags().GetBool("prepare")
    if err != nil {
        fmt.Println(fmt.Errorf("%v", err))
    }

    ex, err := os.Executable()
    if err != nil {
        fmt.Println(fmt.Errorf("%v", err))
    }
    exec_path := path.Dir(ex)

    if prepare {
        err = assets.RestoreAssets(exec_path, "preload_libs")
        if err != nil {
            fmt.Println(fmt.Errorf("couldn't find preload_libs asset %v .", err))
        }
        fmt.Println("extract preload_libs success")
    } else {
        _, err = os.Stat(exec_path + "/" + "preload_libs")
        if err != nil {
            if os.IsNotExist(err) {
                err = assets.RestoreAssets(exec_path, "preload_libs")
                if err != nil {
                    fmt.Println(fmt.Errorf("couldn't find preload_libs asset %v .", err))
                }
                fmt.Println("auto extract preload_libs, plz run command again")
                command.Flag("prepare").Value.Set("true")
            }
        }
    }
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
    rootCmd.CompletionOptions.DisableDefaultCmd = true
    err := rootCmd.Execute()
    if err != nil {
        os.Exit(1)
    }
}

func init() {
    cobra.EnablePrefixMatching = true
    var globalFlags = GlobalFlags{}
    rootCmd.PersistentFlags().BoolVarP(&globalFlags.Prepare, "prepare", "", false, "prepare libs")
    rootCmd.PersistentFlags().BoolVarP(&globalFlags.UnwindStack, "unwindstack", "", false, "enable unwindstack")
    rootCmd.PersistentFlags().BoolVarP(&globalFlags.ShowRegs, "show-regs", "", false, "show regs")
    rootCmd.PersistentFlags().BoolVarP(&globalFlags.Debug, "debug", "d", false, "enable debug logging")
    rootCmd.PersistentFlags().Uint64VarP(&globalFlags.Pid, "pid", "p", defaultPid, "if pid is 0 then we target all pids")
    rootCmd.PersistentFlags().Uint64VarP(&globalFlags.Uid, "uid", "u", defaultUid, "if uid is 0 then we target all users")
    rootCmd.PersistentFlags().StringVarP(&globalFlags.loggerFile, "log-file", "l", "", "-l save the packets to file")
    rootCmd.PersistentFlags().BoolVarP(&globalFlags.Quiet, "quiet", "", false, "use with --log-file, wont logging to terminal when used")
}
