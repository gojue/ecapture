/*
Copyright © 2022 CFC4N <cfc4n.cs@gmail.com>

*/
package cmd

import (
	"ecapture/cli/cobrautl"
	"os"

	"github.com/spf13/cobra"
)

const (
	cliName        = "ecapture"
	cliDescription = "capture text SSL content without CA cert by ebpf hook."
)

var (
	GitVersion  = "v0.1.0"
	ReleaseDate = "2022-03-16"
)

const (
	defaultPid uint64 = 0
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:        cliName,
	Short:      cliDescription,
	SuggestFor: []string{"ecapture"},

	Long: `ecapture是一款无需安装CA证书，即可抓去HTTPS、TLS等明文数据包的工具。
也可以捕获bash的命令，适用于安全审计场景。包括mysqld的数据库审计等。
仓库地址: https://github.com/ehids/ecapture
`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

func usageFunc(c *cobra.Command) error {
	//fmt.Println("repo: https://github.com/ehids/ecapture")
	//fmt.Println("capture text SSL content without CA cert by ebpf hook.")
	//fmt.Printf("process pid: %d\n", os.Getpid())
	return cobrautl.UsageFunc(c, GitVersion, ReleaseDate)
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	rootCmd.SetUsageFunc(usageFunc)
	rootCmd.SetHelpTemplate(`{{.UsageString}}`)
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.EnablePrefixMatching = true
	var globalFlags = GlobalFlags{}
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.cli.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	//rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	rootCmd.PersistentFlags().BoolVar(&globalFlags.Debug, "debug", false, "enable debug logging")
	rootCmd.PersistentFlags().BoolVar(&globalFlags.IsHex, "hex", false, "print byte strings as hex encoded strings")
	rootCmd.PersistentFlags().Uint64VarP(&globalFlags.Pid, "pid", "p", defaultPid, "if target_pid is 0 then we target all pids")
}
