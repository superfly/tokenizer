package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"os"

	"github.com/superfly/macaroon"
	"github.com/superfly/tokenizer"
	tkmac "github.com/superfly/tokenizer/macaroon"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	switch os.Args[1] {
	case "gen":
		if len(os.Args) != 3 {
			usage()
		}
		doGenerateSecret(os.Args[2])
	case "gen-macaroon":
		doGenerateMacararoon()
	default:
		if _, err := url.Parse(os.Args[1]); err != nil {
			usage()
		}
		doCurl(os.Args[1])
	}
}

func doCurl(url string) {
	var (
		proxyURL     = mustGetEnv("PROXY_URL")
		authToken    = mustGetEnv("AUTH_TOKEN")
		sealedSecret = mustGetEnv("SEALED_SECRET")
	)

	client, err := tokenizer.Client(
		proxyURL,
		tokenizer.WithAuth(authToken),
		tokenizer.WithSecret(sealedSecret, nil),
	)
	if err != nil {
		fatalf("bad params: %s", err)
	}

	resp, err := client.Get(url)
	if err != nil {
		fatalf("failed to get: %s", err)
	}

	io.Copy(os.Stdout, resp.Body)

	os.Exit(0)
}

func doGenerateSecret(secretToken string) {
	var (
		sealKey        = mustGetEnv("SEAL_KEY")
		authToken      = os.Getenv("AUTH_TOKEN")
		hexMacaroonKey = os.Getenv("MACAROON_KEY")
	)

	if authToken != "" && hexMacaroonKey != "" {
		fatalln("cannot specify AUTH_TOKEN and MACAROON_KEY")
	}

	var authConfig tokenizer.AuthConfig
	if hexMacaroonKey != "" {
		key, err := hex.DecodeString(hexMacaroonKey)
		if err != nil {
			fatalf("MACAROON_KEY must be hex encoded: %s", err)
		}

		mac, err := macaroon.New(tkmac.KeyFingerprint(key), tkmac.Location, key)
		if err != nil {
			fatalf("failed to generate macaroon: %s", err)
		}

		tok, err := mac.Encode()
		if err != nil {
			fatalf("failed to encode macaroon: %s", err)
		}

		authToken = macaroon.ToAuthorizationHeader(tok)
		authConfig = tokenizer.NewMacaroonAuthConfig(key)
	} else {
		if authToken == "" {
			authToken = randHex(8)
		}
		authConfig = tokenizer.NewBearerAuthConfig(authToken)
	}

	var (
		secret = &tokenizer.Secret{
			AuthConfig:      authConfig,
			ProcessorConfig: &tokenizer.InjectProcessorConfig{Token: secretToken},
		}
	)

	sealedSecret, err := secret.Seal(sealKey)
	if err != nil {
		fatalf("seal secret: %s", err)
	}

	fmt.Printf("export AUTH_TOKEN=\"%s\"\nexport SEALED_SECRET=\"%s\"\n", authToken, sealedSecret)
	os.Exit(0)
}

func doGenerateMacararoon() {
	hexMacaroonKey := mustGetEnv("MACAROON_KEY")
	macaroonKey, err := hex.DecodeString(hexMacaroonKey)
	if err != nil {
		fatalf("bad MACAROON_KEY: %s", err)
	}

	m, err := macaroon.New(tkmac.KeyFingerprint(macaroonKey), tkmac.Location, macaroonKey)
	if err != nil {
		fatalf("failed to generate macaroon: %s", err)
	}

	tok, err := m.Encode()
	if err != nil {
		fatalf("failed to generate macaroon: %s", err)
	}

	fmt.Printf("export AUTH_TOKEN=\"%s\"\n", macaroon.ToAuthorizationHeader(tok))
	os.Exit(0)
}

func mustGetEnv(key string) string {
	val := os.Getenv(key)
	if val == "" {
		fatalf("missing %s\n", key)
	}
	return val
}

func usage() {
	fatalln("Usage:\n\tcurl <url>\n\tcurl gen <token>")
}

func fatalln(args ...any) {
	fmt.Fprintln(os.Stderr, args...)
	os.Exit(1)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format, args...)
	os.Exit(1)
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
