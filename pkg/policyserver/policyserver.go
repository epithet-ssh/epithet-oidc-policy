package policyserver

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/epithet-ssh/epithet-oidc/pkg/authenticator"
	"github.com/epithet-ssh/epithet-oidc/pkg/authorizer"
	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/gorilla/context"
)

type policyServer struct {
	authenticator *authenticator.Authenticator
	authorizer    *authorizer.Authorizer
	httpClient    *http.Client
}

type policyRequest struct {
	Token string `json:"token"`
}

// New creates a new Policy Server which needs to then
// be atatched to some http server, a la
// `http.ListenAndServeTLS(...)`
func New(authenticator *authenticator.Authenticator, authorizer *authorizer.Authorizer, options ...Option) http.Handler {
	ps := &policyServer{
		authenticator: authenticator,
		authorizer:    authorizer,
	}

	for _, o := range options {
		o.apply(ps)
	}

	if ps.httpClient == nil {
		ps.httpClient = &http.Client{
			Timeout: time.Second * 30,
		}
	}

	return ps
}

// Option configures the agent
type Option interface {
	apply(*policyServer)
}

type optionFunc func(*policyServer)

func (f optionFunc) apply(a *policyServer) {
	f(a)
}

// WithHTTPClient specifies the http client to use
func WithHTTPClient(httpClient *http.Client) Option {
	return optionFunc(func(s *policyServer) {
		s.httpClient = httpClient
	})
}

func (s *policyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	r.Body.Close()

	pr := policyRequest{}
	err = json.Unmarshal(buf, &pr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	user, err := s.authenticator.Authenticate(pr.Token)
	if err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	authorization, err := s.authorizer.Authorize(user)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	context.Set(r, "user", user)
	context.Set(r, "groups", authorization.Groups)
	context.Set(r, "expiration", authorization.Expiration)
	context.Set(r, "extensions", authorization.Extensions)

	s.getCertParams(w, r)
}

func (s *policyServer) getCertParams(w http.ResponseWriter, r *http.Request) {
	certParams := ca.CertParams{
		Identity:   context.Get(r, "user").(string),
		Names:      context.Get(r, "groups").([]string),
		Expiration: context.Get(r, "expiration").(time.Duration),
		Extensions: context.Get(r, "extensions").(map[string]string),
	}
	bytes, err := json.Marshal(certParams)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(bytes)
}
