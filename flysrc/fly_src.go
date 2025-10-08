package flysrc

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	headerFlySrc           = "Fly-Src"
	headerFlySrcSignature  = "Fly-Src-Signature"
	flySrcSignatureKeyPath = "/.fly/fly-src.pub"

	maxFlySrcAge = 30 * time.Second
)

var VerifyKey = readFlySrcKey(flySrcSignatureKeyPath)

var FlyProxyNet = net.IPNet{
	IP:   net.ParseIP("172.16.0.0"),
	Mask: net.CIDRMask(16, 32),
}

type Parsed struct {
	Org       string
	App       string
	Instance  string
	Timestamp time.Time
}

func FromRequest(req *http.Request) (*Parsed, error) {
	if p := FlySrcFromContext(req.Context()); p != nil {
		return p, nil
	}

	srcHdr := req.Header.Get(headerFlySrc)
	if srcHdr == "" {
		return nil, errors.New("missing Fly-Src header")
	}

	sigHdr := req.Header.Get(headerFlySrcSignature)
	if sigHdr == "" {
		return nil, errors.New("missing Fly-Src signature")
	}

	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return nil, errors.New("fly-src from malformed remote address")
	}

	peerIp := net.ParseIP(host)
	if peerIp == nil {
		return nil, errors.New("fly-src from malformed ip")
	}

	// The fly-src is only trusted if it comes from fly-proxy, which
	// means it will arrive to the service_ip (127.19.x.x/16) from 172.16.x.x/16.
	if !FlyProxyNet.Contains(peerIp) {
		return nil, errors.New("fly-src is not from fly-proxy")
	}

	return verifyAndParseFlySrc(srcHdr, sigHdr, VerifyKey)
}

func verifyAndParseFlySrc(srcHdr, sigHdr string, key ed25519.PublicKey) (*Parsed, error) {
	sig, err := base64.StdEncoding.DecodeString(sigHdr)
	if err != nil {
		return nil, fmt.Errorf("bad Fly-Src signature: %w", err)
	}

	if !ed25519.Verify(key, []byte(srcHdr), sig) {
		return nil, errors.New("bad Fly-Src signature")
	}

	p, err := parseFlySrc(srcHdr)
	if err != nil {
		return nil, fmt.Errorf("bad Fly-Src header: %w", err)
	}

	if p.age() > maxFlySrcAge {
		return nil, fmt.Errorf("expired Fly-Src header")
	}

	return p, nil
}

func parseFlySrc(hdr string) (*Parsed, error) {
	var ret Parsed

	parts := strings.Split(hdr, ";")
	if n := len(parts); n != 4 {
		return nil, fmt.Errorf("malformed Fly-Src header (%d parts)", n)
	}

	for _, part := range parts {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("malformed Fly-Src header (missing =)")
		}

		switch k {
		case "org":
			ret.Org = v
		case "app":
			ret.App = v
		case "instance":
			ret.Instance = v
		case "ts":
			tsi, err := strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf("malformed Fly-Src timestamp: %w", err)
			}

			ret.Timestamp = time.Unix(int64(tsi), 0)
		default:
			return nil, fmt.Errorf("malformed Fly-Src header (unknown key: %q)", k)
		}
	}

	if ret.Org == "" || ret.App == "" || ret.Instance == "" || ret.Timestamp.IsZero() {
		return nil, fmt.Errorf("malformed Fly-Src header (missing parts)")
	}

	return &ret, nil
}

func (p *Parsed) String() string {
	return fmt.Sprintf("instance=%s;app=%s;org=%s;ts=%d", p.Instance, p.App, p.Org, p.Timestamp.Unix())
}

func (p *Parsed) Sign(key ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(p.String())))
}

func (p *Parsed) age() time.Duration {
	return time.Since(p.Timestamp)
}

func readFlySrcKey(path string) ed25519.PublicKey {
	hk, err := os.ReadFile(path)
	if err != nil {
		logrus.WithError(err).Warn("failed to read Fly-Src public key")
		return nil
	}

	if size := len(hk); hex.DecodedLen(size) != ed25519.PublicKeySize {
		logrus.WithField("size", size).Warn("bad Fly-Src public key size")
		return nil
	}

	key := make(ed25519.PublicKey, ed25519.PublicKeySize)
	if _, err := hex.Decode(key, hk); err != nil {
		logrus.WithError(err).Warn("bad Fly-Src public key")
		return nil
	}

	return key
}
