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
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/superfly/tokenizer"

	"github.com/superfly/flysrc-go"
)

var serveUsage = `
tokenizer serve runs an HTTP proxy that injects third party authentication credentials into requests

Environment:

    OPEN_KEY         - Hex encoded curve25519 private key. You can provide 32
                       random, hex encoded bytes. The log output will contain
                       the associated public key.
    LISTEN_ADDRESS   - The host:port address to listen at. Default: ":8080"
    FILTERED_HEADERS - Comma separated list of headers to filter from client
                       requests.
    OPEN_PROXY       - If true, allow proxy to be used without any sealed secrets.
    USE_FLYSRC       - If true, use /.fly/fly-src.pub to process fly-src headers.
    REQUIRE_FLYSRC   - If true, reject requests that do not have a valid fly-src header.
    DEBUG            - If true, enables debug logging.
    DEBUG_TCP        - If true, enables debug logging of connections.
`

func runServe(cmd string, args []string) {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	var (
		openKey       = fs.String("open-key", os.Getenv("OPEN_KEY"), "private key for opening sealed tokens")
		listenAddress = fs.String("listen-address", ListenAddress, "address to listen on")
		debug         = fs.String("debug", os.Getenv("DEBUG"), "turn on debug logging")
		debugTcp      = fs.String("debug-tcp", os.Getenv("DEBUG_TCP"), "debug TCP if set to true or 1")
		hostNames     = fs.String("hostnames", os.Getenv("TOKENIZER_HOSTNAMES"), "hostnames assigned to the tokenizer")
		openProxy     = fs.String("open-proxy", os.Getenv("OPEN_PROXY"), "run an open proxy if set to true or 1")
		useFlysrc     = fs.String("use-flysrc", os.Getenv("USE_FLYSRC"), "support fly-src using /.fly/fly-src.pub if set to true or 1")
		requireFlysrc = fs.String("require-flysrc", os.Getenv("REQUIRE_FLYSRC"), "require fly-src to use proxy if set to true or 1")
	)
	parseFlags(fs, serveUsage, args)

	l, err := net.Listen("tcp", *listenAddress)
	if err != nil {
		logrus.WithError(err).Fatal("listen")
	}

	if strToBool(*debugTcp) {
		l = debugListener{l}
	}

	if *openKey == "" {
		fmt.Fprintf(os.Stderr, "missing OPEN_KEY\n")
		os.Exit(1)
	}

	opts := []tokenizer.Option{}

	if hn := *hostNames; hn != "" {
		opts = append(opts, tokenizer.TokenizerHostnames(strings.Split(hn, ",")...))
	}

	if strToBool(*openProxy) {
		opts = append(opts, tokenizer.OpenProxy())
	}

	if strToBool(*requireFlysrc) {
		opts = append(opts, tokenizer.RequireFlySrc())
	}

	if strToBool(*useFlysrc) {
		parser, err := flysrc.New()
		if err != nil {
			logrus.WithError(err).Panic("Error making flysrc parser")
		}

		opts = append(opts, tokenizer.WithFlysrcParser(parser))
	}

	tkz := tokenizer.NewTokenizer(*openKey, opts...)

	if strToBool(*debug) {
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
		"address":  *listenAddress,
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
