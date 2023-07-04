package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/superfly/tokenizer"
)

func init() {
	tokenizer.FilteredHeaders = append(tokenizer.FilteredHeaders,
		"Fly-Client-Ip",
		"Fly-Forwarded-Port",
		"Fly-Forwarded-Proto",
		"Fly-Forwarded-Ssl",
		"Fly-Region",
		"Fly-Request-Id",
		"Fly-Traceparent",
		"Fly-Tracestate",
	)
}

func main() {
	// specify port for local dev
	addr := ":8080"
	if port := os.Getenv("PORT"); port != "" {
		addr = fmt.Sprintf("127.0.0.1:%s", port)
	}

	l, err := net.Listen("tcp", addr)
	if err != nil {
		logrus.WithError(err).Fatal("listen")
	}

	tkz := tokenizer.NewTokenizer(os.Getenv("OPEN_KEY"))

	server := &http.Server{
		Addr:    addr,
		Handler: loggingMiddleware(tkz),
	}

	go func() {
		if err := server.Serve(l); !errors.Is(err, http.ErrServerClosed) {
			logrus.WithError(err).Fatal("listening")
		}
	}()

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
