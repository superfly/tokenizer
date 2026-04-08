package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/superfly/tokenizer"
)

// Package variables can be overridden at build time:
//
//	go build -ldflags="-X 'github.com/superfly/tokenizer/cmd/tokenizer.FilteredHeaders=Foo,Bar,Baz'"
var (
	// Comma separated list of headers to strip from requests.
	FilteredHeaders = ""

	// Address for HTTP proxy to listen at.
	ListenAddress = ":8080"

	Version = ""
)

func init() {
	for _, h := range strings.Split(FilteredHeaders, ",") {
		if h = strings.TrimSpace(h); h != "" {
			tokenizer.FilteredHeaders = append(tokenizer.FilteredHeaders, h)
		}
	}
	for _, h := range strings.Split(os.Getenv("FILTERED_HEADERS"), ",") {
		if h = strings.TrimSpace(h); h != "" {
			tokenizer.FilteredHeaders = append(tokenizer.FilteredHeaders, h)
		}
	}
	if addr := os.Getenv("LISTEN_ADDRESS"); addr != "" {
		ListenAddress = addr
	}
}

func main() {
	cmd := "tokenizer"
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	subCmd := os.Args[1]
	qualCmd := cmd + " " + subCmd
	shiftedArgs := os.Args[2:]
	switch subCmd {
	case "version":
		runVersion(qualCmd, shiftedArgs)
	case "serve":
		runServe(qualCmd, shiftedArgs)
	case "sealkey":
		runSealkey(qualCmd, shiftedArgs)
	case "seal":
		runSeal(qualCmd, shiftedArgs)
	case "unseal":
		runUnseal(qualCmd, shiftedArgs)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", subCmd)
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `
tokenizer is an HTTP proxy that injects third party authentication credentials into requests

Usage:

    tokenizer version [flags] - show version
    tokenizer serve [flags]   - serve requests
    tokenizer sealkey [flags] - show seal key
    tokenizer seal [flags]    - seal a token using the seal key
    tokenizer unseal [flags]  - unseal a sealed token using the open key
`)
}
