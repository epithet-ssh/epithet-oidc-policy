package authorizer

import (
	"encoding/json"
	"os/exec"
	"strings"
	"time"
)

type Authorization struct {
	Groups     []string          `json:"groups"`
	Expiration time.Duration     `json:"expiration"`
	Extensions map[string]string `json:"extensions"`
}

type Authorizer struct {
	Command string
}

// New creates a new Authenticator
func New(command string, options ...Option) (*Authorizer, error) {
	authorizer := &Authorizer{
		Command: command,
	}

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

func (a *Authorizer) Authorize(user string) (authorization *Authorization, err error) {
	authorization = &Authorization{}

	cmd := strings.Split(a.Command, " ")
	for i, e := range cmd {
		if e == "%u" {
			cmd[i] = user
		}
	}
	out, err := exec.Command(cmd[0], cmd[1:]...).Output()
	if err != nil {
		return
	}

	err = json.Unmarshal(out, authorization)
	if err != nil {
		return
	}

	return
}
