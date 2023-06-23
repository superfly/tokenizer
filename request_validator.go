package tokenizer

import (
	"fmt"
	"net/http"

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
	if _, allowed := v[r.URL.Host]; !allowed {
		return fmt.Errorf("%w: secret not valid for %s", ErrBadRequest, r.URL.Host)
	}
	return nil
}

func (v allowedHosts) slice() []string {
	return maps.Keys(v)
}
