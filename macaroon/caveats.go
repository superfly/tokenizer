package macaroon

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/superfly/macaroon"
	"golang.org/x/exp/slices"
)

const (
	CavRequestMethod      = macaroon.CavMinUserDefined + iota // 281474976710656
	CavRequestPath                                            // 281474976710657
	CavRequestPathPrefix                                      // 281474976710658
	CavRequestPathPattern                                     // 281474976710659
	CavRequestHost                                            // 281474976710660
)

type RequestMethod []string

func init()                                              { macaroon.RegisterCaveatType(&RequestMethod{}) }
func (c *RequestMethod) CaveatType() macaroon.CaveatType { return CavRequestMethod }
func (c *RequestMethod) Name() string                    { return "RequestMethod" }

func ConstrainRequestMethod(allowedMethods ...string) macaroon.Caveat {
	c := RequestMethod(allowedMethods)
	return &c
}

func (c *RequestMethod) Prohibits(a macaroon.Access) error {
	ta, ok := a.(*Access)
	if !ok {
		return macaroon.ErrInvalidAccess
	}

	if !slices.Contains(*c, ta.Request.Method) {
		return fmt.Errorf("%w for method %s", macaroon.ErrUnauthorized, ta.Request.Method)
	}

	return nil
}

type RequestPath []string

func init()                                            { macaroon.RegisterCaveatType(&RequestPath{}) }
func (c *RequestPath) CaveatType() macaroon.CaveatType { return CavRequestPath }
func (c *RequestPath) Name() string                    { return "RequestPath" }

func ConstrainRequestPath(allowedPaths ...string) macaroon.Caveat {
	c := RequestPath(allowedPaths)
	return &c
}

func (c *RequestPath) Prohibits(a macaroon.Access) error {
	ta, ok := a.(*Access)
	if !ok {
		return macaroon.ErrInvalidAccess
	}

	if path := ta.Request.URL.EscapedPath(); !slices.Contains(*c, path) {
		return fmt.Errorf("%w for path %s", macaroon.ErrUnauthorized, path)
	}

	return nil
}

type RequestPathPrefix []string

func init()                                                  { macaroon.RegisterCaveatType(&RequestPathPrefix{}) }
func (c *RequestPathPrefix) CaveatType() macaroon.CaveatType { return CavRequestPathPrefix }
func (c *RequestPathPrefix) Name() string                    { return "RequestPathPrefix" }

func ConstrainRequestPathPrefix(allowedPrefixes ...string) macaroon.Caveat {
	c := RequestPathPrefix(allowedPrefixes)
	return &c
}

func (c *RequestPathPrefix) Prohibits(a macaroon.Access) error {
	ta, ok := a.(*Access)
	if !ok {
		return macaroon.ErrInvalidAccess
	}

	path := ta.Request.URL.EscapedPath()
	for _, prefix := range *c {
		if strings.HasPrefix(path, prefix) {
			return nil
		}
	}

	return fmt.Errorf("%w for path %s", macaroon.ErrUnauthorized, path)
}

type RequestPathPattern []string

func init()                                                   { macaroon.RegisterCaveatType(&RequestPathPattern{}) }
func (c *RequestPathPattern) CaveatType() macaroon.CaveatType { return CavRequestPathPattern }
func (c *RequestPathPattern) Name() string                    { return "RequestPathPattern" }

func ConstrainRequestPathPattern(allowedPatternes ...string) macaroon.Caveat {
	c := RequestPathPattern(allowedPatternes)
	return &c
}

func (c *RequestPathPattern) Prohibits(a macaroon.Access) error {
	ta, ok := a.(*Access)
	if !ok {
		return macaroon.ErrInvalidAccess
	}

	path := ta.Request.URL.EscapedPath()
	for _, pattern := range *c {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("%w: invalid regex", macaroon.ErrBadCaveat)
		}
		if re.MatchString(path) {
			return nil
		}
	}

	return fmt.Errorf("%w for path %s", macaroon.ErrUnauthorized, path)
}

type RequestHost []string

func init()                                            { macaroon.RegisterCaveatType(&RequestHost{}) }
func (c *RequestHost) CaveatType() macaroon.CaveatType { return CavRequestHost }
func (c *RequestHost) Name() string                    { return "RequestHost" }

func ConstrainRequestHost(allowedHosts ...string) macaroon.Caveat {
	c := RequestHost(allowedHosts)
	return &c
}

func (c *RequestHost) Prohibits(a macaroon.Access) error {
	ta, ok := a.(*Access)
	if !ok {
		return macaroon.ErrInvalidAccess
	}

	if !slices.Contains(*c, ta.Request.Host) {
		return fmt.Errorf("%w for host %s", macaroon.ErrUnauthorized, ta.Request.Host)
	}

	return nil
}
