package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"

	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type Authenticator struct {
	JwksURL  string
	Issuer   string
	Audience []string
	Jwks     *jose.JSONWebKeySet
}

func (a *Authenticator) GetJWKS() (err error) {
	// TODO Have a better cache MESH-354
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
	a.Jwks = &jwks
	return
}

func (a *Authenticator) Authenticate(token string) (user string, identities []string, err error) {
	tok, err := jwt.ParseSigned(token)
	if err != nil {
		return
	}

	claims := jwt.Claims{}
	addition := struct {
		User   string   `json:"user"`
		Groups []string `json:"groups"`
	}{}
	err = tok.Claims(a.Jwks, &claims, &addition)
	if err != nil {
		return
	}

	for _, aud := range a.Audience {
		err = claims.Validate(jwt.Expected{
			Issuer:   a.Issuer,
			Audience: []string{aud},
			Time:     time.Now(),
		})

		if err == nil {
			break
		}
	}
	if err != nil {
		return
	}

	identities = addition.Groups
	user = addition.User
	return
}
