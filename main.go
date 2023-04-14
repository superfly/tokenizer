package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
)

func main() {
	vault, err := vaultInfraLoginFromEnv()
	if err != nil {
		logrus.Fatal(err)
	}

	server := &http.Server{
		Addr:    "127.0.0.1:8823",
		Handler: newTokenizer(vault),
	}

	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			logrus.Fatal(err)
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
