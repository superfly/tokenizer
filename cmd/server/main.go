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
	"time"

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

	l = debugListener{l}

	tkz := tokenizer.NewTokenizer(os.Getenv("OPEN_KEY"))
	tkz.ProxyHttpServer.Verbose = true

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
