package main

import (
	"fmt"
	"net"
	"time"
)

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
