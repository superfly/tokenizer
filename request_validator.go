package tokenizer

import (
	"fmt"
	"net/http"
	"regexp"

	"golang.org/x/exp/maps"
)

type RequestValidator interface {
	Validate(r *http.Request) error
}

type allowedHosts map[string]struct{}

var _ RequestValidator = allowedHosts(nil)

func AllowHosts(hosts ...string) RequestValidator {
	rh := make(allowedHosts, len(hosts))
	for _, h := range hosts {
		rh[h] = struct{}{}
	}
	return rh
}

func (v allowedHosts) Validate(r *http.Request) error {
	if r.Host == "" {
		return fmt.Errorf("%w: no host in request", ErrBadRequest)
	}
	if _, allowed := v[r.Host]; !allowed {
		return fmt.Errorf("%w: secret not valid for %s", ErrBadRequest, r.Host)
	}
	return nil
}

func (v allowedHosts) slice() []string {
	return maps.Keys(v)
}

type allowedHostPattern regexp.Regexp

var _ RequestValidator = (*allowedHostPattern)(nil)

func AllowHostPattern(pattern *regexp.Regexp) RequestValidator {
	return (*allowedHostPattern)(pattern)
}

func (v *allowedHostPattern) Validate(r *http.Request) error {
	if r.Host == "" {
		return fmt.Errorf("%w: no host in request", ErrBadRequest)
	}
	if match := (*regexp.Regexp)(v).MatchString(r.Host); !match {
		return fmt.Errorf("%w: secret not valid for %s", ErrBadRequest, r.Host)
	}
	return nil
}
