package authorizer

import (
	"time"
)

type Authorization struct {
	Groups     []string
	Expiration time.Duration
	Extensions map[string]string
}

type Authorizer struct {
}

// New creates a new Authenticator
func New(options ...Option) (*Authorizer, error) {
	authorizer := &Authorizer{}

	for _, o := range options {
		o.apply(authorizer)
	}

	return authorizer, nil
}

// Option configures the agent
type Option interface {
	apply(*Authorizer)
}

type optionFunc func(*Authorizer)

func (f optionFunc) apply(a *Authorizer) {
	f(a)
}

func (a *Authorizer) Authorize(user string) (authorization Authorization, err error) {
	groups := []string{
		"group2",
	}
	expiration := 120 * time.Second
	extensions := map[string]string{
		"permit-agent-forwarding": "",
		"permit-pty":              "",
		"permit-user-rc":          "",
	}

	return Authorization{
		Groups:     groups,
		Expiration: expiration,
		Extensions: extensions,
	}, nil
}
