package main

import (
	"flag"
	"fmt"
	"os"
	"runtime/debug"
)

var versionUsage = `
tokenizer version displays the version
`

func runVersion(cmd string, args []string) {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	parseFlags(fs, versionUsage, args)

	fmt.Fprintln(os.Stderr, versionString())
}

func versionString() string {
	if Version != "" {
		return fmt.Sprintf("tokenizer %s", Version)
	} else if bi, ok := debug.ReadBuildInfo(); ok {
		var (
			commit   string
			modified bool
		)
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" {
				commit = s.Value
			}
			if s.Key == "vcs.modified" {
				modified = s.Value == "true"
			}
		}

		switch {
		case modified:
			// dev build
		case bi.Main.Version != "(devel)" && commit != "":
			return fmt.Sprintf("tokenizer %s, commit=%s", bi.Main.Version, commit)
		case bi.Main.Version != "(devel)":
			return fmt.Sprintf("tokenizer %s", bi.Main.Version)
		case commit != "":
			return fmt.Sprintf("tokenizer commit=%s", commit)
		}
	}
	return "tokenizer development build"
}
