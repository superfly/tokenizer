package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"
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
	l, err := net.Listen("tcp", ListenAddress)
	if err != nil {
		logrus.WithError(err).Fatal("listen")
	}

	key := os.Getenv("OPEN_KEY")
	if key == "" {
		fmt.Fprintf(os.Stderr, "missing OPEN_KEY")
		os.Exit(1)
	}

	tkz := tokenizer.NewTokenizer(key)

	server := &http.Server{Handler: loggingMiddleware(tkz)}

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
