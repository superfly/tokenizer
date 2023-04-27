package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/superfly/tokenizer"
	_ "github.com/superfly/tokenizer/processors/inject"
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

	addr := "0.0.0.0:8080"
	if port := os.Getenv("PORT"); port != "" {
		addr = fmt.Sprintf("127.0.0.1:%s", port)
	}

	tkz := tokenizer.NewTokenizer(ss)
	tkz.ProxyHttpServer.Verbose = true

	l, err := net.Listen("tcp", addr)
	if err != nil {
		logrus.WithError(err).Fatal("listening")
	}

	certPath := os.Getenv("CERT_PATH")
	keyPath := os.Getenv("KEY_PATH")
	if certPath != "" && keyPath != "" {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			logrus.WithError(err).Fatal("load tls")
		}

		l = tls.NewListener(l, &tls.Config{Certificates: []tls.Certificate{cert}})
	}

	l = debugListener{l}

	server := &http.Server{Addr: addr, Handler: tkz}

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
