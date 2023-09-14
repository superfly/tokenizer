package macaroon

import (
	"net/http"
	"time"

	"github.com/superfly/macaroon"
)

type Access struct {
	Request *http.Request
}

var _ macaroon.Access = (*Access)(nil)

func (a *Access) Now() time.Time {
	return time.Now()
}

func (a *Access) Validate() error {
	if a.Request == nil {
		return macaroon.ErrInvalidAccess
	}
	return nil
}
