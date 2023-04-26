package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/superfly/tokenizer"
	_ "github.com/superfly/tokenizer/processors/inject"
)

func main() {
	// vault, err := vaultInfraLoginFromEnv()
	// if err != nil {
	// 	logrus.Fatal(err)
	// }
	// ss := tokenizer.VaultSecretStore(vault)

	ssAuth := os.Getenv("SHARED_SECRET_DIGEST")
	if ssAuth == "" {
		logrus.Fatal("missing SHARED_SECRET_DIGEST environment variable")
	}
	tokenizer.RegisterSharedSecretAuthorizer("secret", ssAuth)

	ssJSON := os.Getenv("SECRET_STORE")
	if ssJSON == "" {
		logrus.Fatal("missing SECRET_STORE environment variable")
	}

	ss := make(tokenizer.StaticSecretStore)
	if err := json.Unmarshal([]byte(ssJSON), &ss); err != nil {
		logrus.WithError(err).Fatal("parsing SECRET_STORE environment variable")
	}

	server := &http.Server{Addr: "127.0.0.1:8823", Handler: tokenizer.NewTokenizer(ss)}

	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
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
