package tokenizer

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"time"

	"github.com/btoews/fakeca"
	"github.com/elazarl/goproxy"
)

type ca interface {
	goproxy.CertStorage
	Chain() []*x509.Certificate
}

type fakeCA struct {
	*fakeca.Identity
}

var _ ca = new(fakeCA)

func newFakeCA() *fakeCA {
	return &fakeCA{fakeca.New(fakeca.IsCA)}
}

// Fetch implements goproxy.CertStorage
func (c *fakeCA) Fetch(hostname string, gen func() (*tls.Certificate, error)) (*tls.Certificate, error) {
	certOpts := []fakeca.Option{
		fakeca.Subject(pkix.Name{CommonName: hostname}),
		fakeca.NotAfter(time.Now().Add(time.Hour)),
	}

	if ip := net.ParseIP(hostname); ip != nil {
		certOpts = append(certOpts, fakeca.IPAddresses(ip))
	} else {
		certOpts = append(certOpts, fakeca.DNSNames(hostname))
	}

	hostIdentity := c.Issue(certOpts...)
	chain := hostIdentity.Chain()
	rawChain := make([][]byte, 0, len(chain))
	for _, cert := range chain {
		rawChain = append(rawChain, cert.Raw)
	}

	return &tls.Certificate{
		Certificate: rawChain,
		PrivateKey:  hostIdentity.PrivateKey,
		Leaf:        hostIdentity.Certificate,
	}, nil
}
