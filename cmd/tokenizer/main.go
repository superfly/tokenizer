package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/superfly/tokenizer"
	"golang.org/x/exp/slices"
)

// Package variables can be overridden at build time:
//
//	go build -ldflags="-X 'github.com/superfly/tokenizer/cmd/tokenizer.FilteredHeaders=Foo,Bar,Baz'"
var (
	// Comma separated list of headers to strip from requests.
	FilteredHeaders = ""

	// Address for HTTP proxy to listen at.
	ListenAddress = ":8080"
)

var (
	versionFlag = flag.Bool("version", false, "print the version number")
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
	flag.Usage = usage
	flag.Parse()

	switch {
	case *versionFlag:
		runVersion()
	default:
		runServe()
	}

}

func runServe() {
	l, err := net.Listen("tcp", ListenAddress)
	if err != nil {
		logrus.WithError(err).Fatal("listen")
	}

	if len(os.Getenv("DEBUG_TCP")) != 0 {
		l = debugListener{l}
	}

	key := os.Getenv("OPEN_KEY")
	if key == "" {
		fmt.Fprintf(os.Stderr, "missing OPEN_KEY")
		os.Exit(1)
	}

	opts := []tokenizer.Option{}

	if hn := os.Getenv("TOKENIZER_HOSTNAMES"); hn != "" {
		opts = append(opts, tokenizer.TokenizerHostnames(strings.Split(hn, ",")...))
	}

	if slices.Contains([]string{"1", "true"}, os.Getenv("OPEN_PROXY")) {
		opts = append(opts, tokenizer.OpenProxy())
	}

	tkz := tokenizer.NewTokenizer(key, opts...)

	if len(os.Getenv("DEBUG")) != 0 {
		tkz.ProxyHttpServer.Verbose = true
		tkz.ProxyHttpServer.Logger = logrus.StandardLogger()
	}

	server := &http.Server{Handler: tkz}

	go func() {
		if err := server.Serve(l); !errors.Is(err, http.ErrServerClosed) {
			logrus.WithError(err).Fatal("listening")
		}
	}()

	logrus.WithFields(logrus.Fields{
		"address":  ListenAddress,
		"seal_key": tkz.SealKey(),
	}).Info("listening")

	handleSignals(server)
}

func handleSignals(server *http.Server) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigs
	logrus.WithField("signal", sig).Info("graceful shutdown")

	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := server.Shutdown(context.Background()); err != nil {
			logrus.WithError(err).Warn("graceful shutdown")
		}
	}()

	select {
	case <-done:
	case <-sigs:
		logrus.Info("immediate shutdown")
		if err := server.Close(); err != nil {
			logrus.WithError(err).Warn("immediate shutdown")
		}
	}
}

var Version = ""

func runVersion() {
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

func usage() {
	fmt.Fprintf(os.Stderr, `
tokenizer is an HTTP proxy that injects third party authentication credentials into requests

Usage:

    tokenizer [flags]

Flags:
    -version      prints the version
    -help         prints this message

Configuration — tokenizer is configured using the following environment variables:

    OPEN_KEY         - Hex encoded curve25519 private key. You can provide 32
                       random, hex encoded bytes. The log output will contain
                       the associated public key.
    LISTEN_ADDRESS   - The host:port address to listen at. Default: ":8080"
    FILTERED_HEADERS - Comma separated list of headers to filter from client
                       requests.
`[1:])
}

type debugListener struct {
	net.Listener
}

func (dl debugListener) Accept() (net.Conn, error) {
	c, err := dl.Listener.Accept()
	if err == nil {
		c = debugConn{c}
	}
	return c, err
}

type debugConn struct {
	c net.Conn
}

func (dc debugConn) Read(b []byte) (int, error) {
	n, err := dc.c.Read(b)
	if err == nil {
		fmt.Printf("<- %#v\n", string(b[:n]))
	}
	return n, err
}

func (dc debugConn) Write(b []byte) (int, error) {
	fmt.Printf("-> %#v\n", string(b))
	return dc.c.Write(b)
}

func (dc debugConn) Close() error {
	return dc.c.Close()
}

func (dc debugConn) LocalAddr() net.Addr {
	return dc.c.LocalAddr()
}

func (dc debugConn) RemoteAddr() net.Addr {
	return dc.c.RemoteAddr()
}

func (dc debugConn) SetDeadline(t time.Time) error {
	return dc.c.SetDeadline(t)
}

func (dc debugConn) SetReadDeadline(t time.Time) error {
	return dc.c.SetReadDeadline(t)
}

func (dc debugConn) SetWriteDeadline(t time.Time) error {
	return dc.c.SetWriteDeadline(t)
}
