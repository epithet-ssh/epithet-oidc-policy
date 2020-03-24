package authenticator

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"time"

	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type Authenticator struct {
	JwksURL  string
	Issuer   string
	Audience string
	ClientID string
	jwks     *jose.JSONWebKeySet
}

// New creates a new Authenticator
func New(jwksURL, issuer, audience, clientID string, options ...Option) (*Authenticator, error) {
	authenticator := &Authenticator{
		JwksURL:  jwksURL,
		Issuer:   issuer,
		Audience: audience,
		ClientID: clientID,
	}

	for _, o := range options {
		o.apply(authenticator)
	}

	err := authenticator.GetJWKS()
	return authenticator, err
}

// Option configures the agent
type Option interface {
	apply(*Authenticator)
}

type optionFunc func(*Authenticator)

func (f optionFunc) apply(a *Authenticator) {
	f(a)
}

func (a *Authenticator) GetJWKS() (err error) {
	resp, err := http.Get(a.JwksURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	jwks := jose.JSONWebKeySet{}
	err = json.Unmarshal(responseBody, &jwks)
	if err != nil {
		return
	}
	a.jwks = &jwks
	return
}

func (a *Authenticator) Authenticate(token string) (string, error) {
	tok, err := jwt.ParseSigned(token)
	if err != nil {
		return "", err
	}

	claims := jwt.Claims{}
	addition := struct {
		ClientID string `json:"cid"`
	}{}
	err = tok.Claims(a.jwks, &claims, &addition)
	if err != nil {
		return "", err
	}
	err = claims.Validate(jwt.Expected{
		Issuer:   a.Issuer,
		Audience: []string{a.Audience},
		Time:     time.Now(),
	})
	if err != nil {
		return "", err
	}
	if addition.ClientID != a.ClientID {
		return "", errors.New("invalid client id")
	}

	return claims.Subject, nil
}
