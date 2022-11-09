package cmd

import (
    "github.com/spf13/cobra"
)

// GlobalFlags are flags that defined globally
// and are inherited to all sub-commands.
type GlobalFlags struct {
    Quiet       bool
    ShowRegs    bool
    Prepare     bool
    UnwindStack bool
    Debug       bool
    Uid         uint64
    loggerFile  string
}

func getGlobalConf(command *cobra.Command) (conf GlobalFlags, err error) {

    conf.Uid, err = command.Flags().GetUint64("uid")
    if err != nil {
        return
    }

    conf.Debug, err = command.Flags().GetBool("debug")
    if err != nil {
        return
    }

    conf.UnwindStack, err = command.Flags().GetBool("unwindstack")
    if err != nil {
        return
    }

    conf.Prepare, err = command.Flags().GetBool("prepare")
    if err != nil {
        return
    }

    conf.loggerFile, err = command.Flags().GetString("log-file")
    if err != nil {
        return
    }

    conf.Quiet, err = command.Flags().GetBool("quiet")
    if err != nil {
        return
    }

    conf.ShowRegs, err = command.Flags().GetBool("regs")
    if err != nil {
        return
    }

    return
}
