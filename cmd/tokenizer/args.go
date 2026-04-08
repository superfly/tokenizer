package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// parseFlags runs the flagset parser.
// It fails if there are any non-flag arguments.
// On error it prints the default usage and moreUsage and exits.
func parseFlags(fs *flag.FlagSet, moreUsage string, args []string) {
	err := fs.Parse(args)
	if err == nil && len(fs.Args()) > 0 {
		err = fmt.Errorf("unknown arguments: %v\n", strings.Join(fs.Args(), " "))
		fmt.Fprintf(os.Stderr, "%v\n", err)
		fs.Usage()
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", moreUsage)
		os.Exit(1)
	}
}

// strToBool converts a string to a boolean. If there is an error parsing the string
// it returns a default value of false.  Values 1, t, T, TRUE, true, and True return true values.
func strToBool(s string) bool {
	b, _ := strconv.ParseBool(s)
	return b
}
