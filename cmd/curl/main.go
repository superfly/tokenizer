package main

import (
	"fmt"
	"io"
	"os"

	"github.com/superfly/tokenizer"
)

func main() {
	if len(os.Args) != 2 {
		fatalln("Usage: curl <url>")
	}

	var (
		appURL    = os.Args[1]
		proxyURL  = mustGetEnv("PROXY_URL")
		proxyAuth = mustGetEnv("PROXY_AUTH")
		secretKey = mustGetEnv("SECRET_KEY")
	)

	client, err := tokenizer.Client(nil, tokenizer.WithProxy(proxyURL), tokenizer.WithProxyAuth(proxyAuth), tokenizer.WithSecret(secretKey, nil))
	if err != nil {
		fatalf("bad params: %s", err)
	}

	resp, err := client.Get(appURL)
	if err != nil {
		fatalf("failed to get: %s", err)
	}

	io.Copy(os.Stdout, resp.Body)
}

func mustGetEnv(key string) string {
	val := os.Getenv(key)
	if val == "" {
		fatalf("missing %s\n", key)
	}
	return val
}

func fatalln(args ...any) {
	fmt.Println(args...)
	os.Exit(1)
}

func fatalf(format string, args ...any) {
	fmt.Printf(format, args...)
	os.Exit(1)
}
