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
	GitVersion = "v0.0.0_unknow"
	//ReleaseDate = "2022-03-16"
)

const (
	defaultPid uint64 = 0
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:        cliName,
	Short:      cliDescription,
	SuggestFor: []string{"ecapture"},

	Long: `eCapture is a tool that can capture plaintext packets 
such as HTTPS and TLS without installing a CA certificate.
It can also capture bash commands, which is suitable for 
security auditing scenarios, such as database auditing of mysqld, etc.

Repository: https://github.com/ehids/ecapture
`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

func usageFunc(c *cobra.Command) error {
	return cobrautl.UsageFunc(c, GitVersion)
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
	rootCmd.PersistentFlags().BoolVarP(&globalFlags.Debug, "debug", "d", false, "enable debug logging")
	rootCmd.PersistentFlags().BoolVar(&globalFlags.IsHex, "hex", false, "print byte strings as hex encoded strings")
	rootCmd.PersistentFlags().Uint64VarP(&globalFlags.Pid, "pid", "p", defaultPid, "if pid is 0 then we target all pids")
}
