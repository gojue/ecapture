// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// copied from https://github.com/etcd-io/etcd/v3/pkg/cobrautl/help.go

package cobrautl

import (
	"io"
	"strings"
	"text/tabwriter"
	"text/template"

	"github.com/spf13/cobra"
)

var (
	commandUsageTemplate *template.Template
	templFuncs           = template.FuncMap{
		"descToLines": func(s string) []string {
			// trim leading/trailing whitespace and split into slice of lines
			return strings.Split(strings.Trim(s, "\n\t "), "\n")
		},
		"cmdName": func(cmd *cobra.Command, startCmd *cobra.Command) string {
			parts := []string{cmd.Name()}
			for cmd.HasParent() && cmd.Parent().Name() != startCmd.Name() {
				cmd = cmd.Parent()
				parts = append([]string{cmd.Name()}, parts...)
			}
			return strings.Join(parts, " ")
		},
	}
)

func init() {
	commandUsage := `
{{ $cmd := .Cmd }}\
{{ $cmdname := cmdName .Cmd .Cmd.Root }}\
NAME:
{{ if not .Cmd.HasParent }}\
{{printf "\t%s - %s" .Cmd.Name .Cmd.Short}}
{{else}}\
{{printf "\t%s - %s" $cmdname .Cmd.Short}}
{{end}}\

USAGE:
{{printf "\t%s" .Cmd.UseLine}}
{{if .Cmd.Aliases}}\

ALIASES:
{{range .Cmd.Aliases}}{{printf "\t%s\n" .}}{{end}}\
{{end}}\
{{ if not .Cmd.HasParent }}\

VERSION:
{{printf "\t%s" .Version}}
{{end}}\
{{if .Cmd.HasSubCommands}}\

COMMANDS:
{{range .SubCommands}}\
{{ $cmdname := cmdName . $cmd }}\
{{ if .Runnable }}\
{{printf "\t%s\t%s" $cmdname .Short}}
{{end}}\
{{end}}\
{{end}}\
{{ if .Cmd.Long }}\

DESCRIPTION:
{{range $line := descToLines .Cmd.Long}}{{printf "\t%s" $line}}
{{end}}\
{{end}}\
{{if .Cmd.HasExample}}\

EXAMPLES:
{{range $line := descToLines .Cmd.Example}}{{printf "\t%s" $line}}
{{end}}\
{{end}}\
{{if .Cmd.HasLocalFlags}}\

OPTIONS:
{{.Cmd.LocalFlags.FlagUsagesWrapped 100}}\
{{end}}\
{{if .Cmd.HasInheritedFlags}}\

GLOBAL OPTIONS:
{{.Cmd.InheritedFlags.FlagUsagesWrapped 100}}\
{{end}}
`[1:]

	commandUsageTemplate = template.Must(template.New("command_usage").Funcs(templFuncs).Parse(strings.ReplaceAll(commandUsage, "\\\n", "")))
}

func getSubCommands(cmd *cobra.Command) []*cobra.Command {
	var subCommands []*cobra.Command
	for _, subCmd := range cmd.Commands() {
		subCommands = append(subCommands, subCmd)
		subCommands = append(subCommands, getSubCommands(subCmd)...)
	}
	return subCommands
}

func UsageFunc(cmd *cobra.Command, version string) error {
	subCommands := getSubCommands(cmd)
	tabOut := getTabOutWithWriter(cmd.OutOrStdout())
	err := commandUsageTemplate.Execute(tabOut, struct {
		Cmd         *cobra.Command
		SubCommands []*cobra.Command
		Version     string
	}{
		cmd,
		subCommands,
		version,
	})
	if err != nil {
		return err
	}
	err = tabOut.Flush()
	return err
}

func getTabOutWithWriter(writer io.Writer) *tabwriter.Writer {
	aTabOut := new(tabwriter.Writer)
	aTabOut.Init(writer, 0, 8, 1, '\t', 0)
	return aTabOut
}
