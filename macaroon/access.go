package macaroon

import (
	"net/http"
	"time"

	"github.com/superfly/macaroon"
	"github.com/superfly/macaroon/flyio"
	"github.com/superfly/tokenizer/flysrc"
)

type Access struct {
	Request *http.Request
}

var _ macaroon.Access = (*Access)(nil)
var _ flyio.SourceMachineGetter = (*Access)(nil)

func (a *Access) Now() time.Time {
	return time.Now()
}

func (a *Access) Validate() error {
	if a.Request == nil {
		return macaroon.ErrInvalidAccess
	}
	return nil
}

func (a *Access) GetSourceMachine() *string {
	fs, err := flysrc.FromRequest(a.Request)
	if err != nil {
		return nil
	}

	return &fs.Instance
}
