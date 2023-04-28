package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"os"

	"github.com/superfly/tokenizer"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	if os.Args[1] == "gen" {
		if len(os.Args) != 3 {
			usage()
		}
		doGenerateSecret(os.Args[2])
	}

	if _, err := url.Parse(os.Args[1]); err != nil {
		usage()
	}
	doCurl(os.Args[1])
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
		sealKey   = mustGetEnv("SEAL_KEY")
		authToken = randHex(8)
		secret    = &tokenizer.Secret{
			AuthConfig:      tokenizer.NewBearerAuthConfig(authToken),
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
