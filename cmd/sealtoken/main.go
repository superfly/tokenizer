package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/superfly/tokenizer"
)

func wrapToken(token, sealKey, orgSlug, appSlug, targHost, targHdr string, debug bool) (string, error) {
	inj := &tokenizer.InjectProcessorConfig{Token: token}
	secret := tokenizer.Secret{
		AuthConfig: tokenizer.NewFlySrcAuthConfig(
			tokenizer.AllowlistFlySrcOrgs(orgSlug),
			tokenizer.AllowlistFlySrcApps(appSlug),
		),
		ProcessorConfig: inj,
		RequestValidators: []tokenizer.RequestValidator{
			tokenizer.AllowHosts(targHost),
		},
	}

	// If they request a specific header, fill it in verbatim.
	// Otherwise the tokenizer will default to filling in "Authorization: Bearer <token>".
	if targHdr != "" {
		inj.Fmt = "%s"
		inj.Dst = targHdr
	}

	if debug {
		bs, err := json.Marshal(secret)
		if err != nil {
			return "", fmt.Errorf("json.Marshal: %w", err)
		}
		return string(bs), nil
	}

	return secret.Seal(sealKey)
}

func wrapJsonToken(token, sealKey string, debug bool) (string, error) {
	var secret tokenizer.Secret
	if err := json.Unmarshal([]byte(token), &secret); err != nil {
		return "", fmt.Errorf("json.Unmarshal: %w", err)
	}

	if debug {
		bs, err := json.Marshal(secret)
		if err != nil {
			return "", fmt.Errorf("json.Marshal: %w", err)
		}
		return string(bs), nil
	}

	return secret.Seal(sealKey)
}

func tryMain() error {
	defSealKey := os.Getenv("SEAL_KEY")
	sealKey := flag.String("sealkey", defSealKey, "tokenizer seal key, or from environment SEAL_KEY")
	json := flag.Bool("json", false, "create sealed token from json tokenizer secret")
	orgSlug := flag.String("org", "", "allowed org slug")
	appSlug := flag.String("app", "", "allowed app slug")
	targHost := flag.String("host", "", "target host")
	targHdr := flag.String("header", "", "target header to fill. Defaults to the bearer authorization header")
	debug := flag.Bool("debug", false, "show json of sealed secret")

	prog := os.Args[0]
	flag.Parse()
	args := flag.Args()

	if len(args) != 1 {
		fmt.Printf("usage: %s [flags] token\n", prog)
		flag.PrintDefaults()
		return fmt.Errorf("token unspecified")
	}

	if *sealKey == "" {
		return fmt.Errorf("sealkey unspecified")
	}

	if *json {
		j := args[0]
		wrapped, err := wrapJsonToken(j, *sealKey, *debug)
		if err != nil {
			return fmt.Errorf("wrapJsonToken: %w", err)
		}
		fmt.Printf("%s\n", wrapped)
	} else {
		if *orgSlug == "" {
			return fmt.Errorf("org unspecified")
		}
		if *appSlug == "" {
			return fmt.Errorf("app unspecified")
		}
		if *targHost == "" {
			return fmt.Errorf("target host unspecified")
		}

		token := args[0]

		wrapped, err := wrapToken(token, *sealKey, *orgSlug, *appSlug, *targHost, *targHdr, *debug)
		if err != nil {
			return fmt.Errorf("wrapToken: %w", err)
		}
		fmt.Printf("%s\n", wrapped)
	}
	return nil
}

func main() {
	if err := tryMain(); err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}
}
