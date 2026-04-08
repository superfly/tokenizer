package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/superfly/tokenizer"
)

var sealkeyUsage = `
tokenizer sealkey displays the sealing key matching the tokenizer's OPEN_KEY

Environment variables:

    OPEN_KEY         - Hex encoded curve25519 private key. You can provide 32
                       random, hex encoded bytes. The log output will contain
                       the associated public key.
`

func runSealkey(cmd string, args []string) {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	var (
		openKey = fs.String("open-key", os.Getenv("OPEN_KEY"), "private key for opening sealed tokens")
	)
	parseFlags(fs, sealkeyUsage, args)

	if *openKey == "" {
		fmt.Fprintf(os.Stderr, "missing OPEN_KEY\n")
		os.Exit(1)
	}

	tkz := tokenizer.NewTokenizer(*openKey)
	fmt.Fprintf(os.Stderr, "export SEAL_KEY=%v\n", tkz.SealKey())
}
