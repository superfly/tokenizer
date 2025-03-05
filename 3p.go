package tokenizer

import (
	"net/http"
	"net/url"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/superfly/macaroon"
	"github.com/superfly/macaroon/bundle"
	"github.com/superfly/macaroon/flyio"
	"github.com/superfly/macaroon/resset"
	"github.com/superfly/macaroon/tp"
	tkmac "github.com/superfly/tokenizer/macaroon"
)

// thirdParty is a discharge service that forces macaroons to be used via the
// tokenizer. This works be adding a third-party caveat to macaroons, pointing
// at the tokenizer. The tokenizer implements the tp discharge protocol, but
// gives discharge tokens that strip all permissions from the macaroon. However,
// if a proxied request contains macaroons with our tp caveat, we give a real
// discharge and add that to the proxied request.
type thirdParty struct {
	*tp.TP
}

func (s *thirdParty) isDischargeRequest(r *http.Request) bool {
	if s == nil {
		return false
	}

	u, err := url.Parse(s.Location)
	if err != nil {
		return false
	}
	if u.Path == "" {
		u.Path = "/"
	}

	u = u.JoinPath(tp.InitPath)

	return r.Host == u.Host && r.URL.Path == u.Path
}

func (s *thirdParty) serveFakeDischarge(w http.ResponseWriter, r *http.Request) {
	s.InitRequestMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actionNone := resset.ActionNone
		s.RespondDischarge(w, r, &actionNone)
	})).ServeHTTP(w, r)
}

func (s *thirdParty) injectRealDischarge(r *http.Request, log logrus.FieldLogger) {
	if s == nil {
		log.Debug("thirdParty: no thirdParty")
		return
	}

	auth := r.Header.Get("Authorization")
	if auth == "" {
		log.Debug("thirdParty: no Authorization")
		return
	}

	stripDischarges := bundle.Not(bundle.LocationFilter(s.Location).Predicate())
	bun, err := flyio.ParseBundleWithFilter(auth, stripDischarges)
	if err != nil {
		log.WithError(err).Debug("thirdParty: failed to parse bundle")
		return
	}

	if err := bun.Discharge(s.Location, s.Key, s.discharger(r)); err != nil {
		log.WithError(err).Info("thirdParty: failed to discharge")
		return
	}

	log.Debug("thirdParty: injected real discharge")
	r.Header.Set("Authorization", bun.Header())
}

func (s *thirdParty) discharger(r *http.Request) bundle.Discharger {
	return func(cavs []macaroon.Caveat) ([]macaroon.Caveat, error) {
		if err := macaroon.NewCaveatSet(cavs...).Validate(&tkmac.Access{Request: r}); err != nil {
			return nil, err
		}

		return []macaroon.Caveat{
			&macaroon.ValidityWindow{
				NotBefore: time.Now().Add(-time.Minute).Unix(),
				NotAfter:  time.Now().Add(time.Minute).Unix(),
			},
		}, nil
	}
}
