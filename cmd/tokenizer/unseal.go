package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/superfly/tokenizer"
)

var unsealUsage = `
tokenizer unseal opens a sealed token using the tokenizer's OPEN_KEY and displays its contents in JSON format

Environment variables:

    OPEN_KEY         - Hex encoded curve25519 private key. You can provide 32
                       random, hex encoded bytes. The log output will contain
                       the associated public key.
`

func runUnseal(cmd string, args []string) {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	var (
		openKey = fs.String("open-key", os.Getenv("OPEN_KEY"), "private key for opening sealed tokens")
		token   = fs.String("token", "", "sealed token")
	)
	parseFlags(fs, unsealUsage, args)

	if *openKey == "" {
		fmt.Fprintf(os.Stderr, "missing OPEN_KEY\n")
		os.Exit(1)
	}

	if *token == "" {
		fmt.Fprintf(os.Stderr, "missing sealed token\n")
		os.Exit(1)
	}

	secret, err := tokenizer.NewTokenizer(*openKey).OpenSealed(*token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "token: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("%v\n", string(secret))
}
