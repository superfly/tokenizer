package tokenizer

import (
	"errors"
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
	host := r.URL.Host
	if host == "" {
		host = r.Host
	}
	if host == "" {
		return errors.New("coun't find host in request")
	}
	if _, allowed := v[host]; !allowed {
		return fmt.Errorf("%w: secret not valid for %s", ErrBadRequest, host)
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
	host := r.URL.Host
	if host == "" {
		host = r.Host
	}
	if host == "" {
		return errors.New("coun't find host in request")
	}
	if match := (*regexp.Regexp)(v).MatchString(host); !match {
		return fmt.Errorf("%w: secret not valid for %s", ErrBadRequest, host)
	}
	return nil
}
