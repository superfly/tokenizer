package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"

	"github.com/superfly/tokenizer"
)

func unseal(sealedToken, openKey string) error {
	// Decode the private key from hex
	privBytes, err := hex.DecodeString(openKey)
	if err != nil {
		return fmt.Errorf("invalid open key: %w", err)
	}
	if len(privBytes) != 32 {
		return fmt.Errorf("open key must be 32 bytes, got %d", len(privBytes))
	}
	priv := (*[32]byte)(privBytes)

	// Derive public key from private key
	pub := new([32]byte)
	curve25519.ScalarBaseMult(pub, priv)

	// Decode the sealed token from base64
	ctSecret, err := base64.StdEncoding.DecodeString(sealedToken)
	if err != nil {
		return fmt.Errorf("invalid base64 encoding: %w", err)
	}

	// Unseal the token
	jsonSecret, ok := box.OpenAnonymous(nil, ctSecret, pub, priv)
	if !ok {
		return fmt.Errorf("failed to unseal token - invalid key or corrupted data")
	}

	// Parse the secret JSON
	var secret tokenizer.Secret
	if err := json.Unmarshal(jsonSecret, &secret); err != nil {
		return fmt.Errorf("invalid secret JSON: %w", err)
	}

	// Pretty print the secret
	prettyJSON, err := json.MarshalIndent(secret, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to format JSON: %w", err)
	}

	fmt.Println(string(prettyJSON))
	return nil
}

func main() {
	openKey := flag.String("openkey", os.Getenv("OPEN_KEY"), "Open key (private key) in hex, or from OPEN_KEY env var")
	flag.Parse()

	args := flag.Args()
	if len(args) != 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <sealed-token>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *openKey == "" {
		fmt.Fprintf(os.Stderr, "Error: open key not specified (use -openkey flag or OPEN_KEY env var)\n")
		os.Exit(1)
	}

	sealedToken := args[0]
	if err := unseal(sealedToken, *openKey); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
