/*
Copyright © 2022 CFC4N <cfc4n.cs@gmail.com>

*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// mysqld57Cmd represents the mysqld57 command
var mysqld57Cmd = &cobra.Command{
	Use:   "mysqld57",
	Short: "capture sql queries from mysqld >5.7 .",
	Long: ` 稍后上传，研发中:

需要适配mysql56、mysql57、mariadbd等。`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("coming soon")
	},
}

func init() {
	rootCmd.AddCommand(mysqld57Cmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// mysqld57Cmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// mysqld57Cmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
