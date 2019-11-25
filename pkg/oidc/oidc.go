package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/pkg/browser"
	"golang.org/x/oauth2"
)

// Authenticator performs OpenID Connect
type Authenticator struct {
	ClientID      string
	IssuerURL     string
	RedirectURL   string
	ListenAddress string
	Timeout       time.Duration

	payload string
	done    chan error

	tokenVerifier            *oidc.IDTokenVerifier
	state                    string
	oauthConfig              oauth2.Config
	codeChallengeParam       oauth2.AuthCodeOption
	codeChallengeMethodParam oauth2.AuthCodeOption
	codeVerifierParam        oauth2.AuthCodeOption
}

// Payload holds tokens after authentication
type Payload struct {
	IDToken     string
	AccessToken string
}

func (a *Authenticator) succeeded(w http.ResponseWriter) {
	fmt.Fprintf(w, "authenticated")
	a.done <- nil
}

func (a *Authenticator) failed(w http.ResponseWriter, err error) {
	fmt.Fprintf(w, err.Error())
	a.done <- err
}

func (a *Authenticator) callbackHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("state") != a.state {
		a.failed(w, errors.New("state did not match"))
		return
	}

	oauth2Token, err := a.oauthConfig.Exchange(r.Context(), r.URL.Query().Get("code"), a.codeVerifierParam)
	if err != nil {
		a.failed(w, err)
		return
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		a.failed(w, errors.New("No id_token field in oauth2 token"))
		return
	}
	_, err = a.tokenVerifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		a.failed(w, err)
		return
	}

	payload := Payload{
		IDToken:     rawIDToken,
		AccessToken: oauth2Token.AccessToken,
	}
	payloadString, err := json.Marshal(payload)
	if err != nil {
		a.failed(w, err)
	}
	a.payload = string(payloadString)
	a.succeeded(w)
	return
}

func (a *Authenticator) generateState(len int) string {
	randomBytes := make([]byte, len)
	rand.Read(randomBytes)
	return base64.RawURLEncoding.EncodeToString(randomBytes)[:len]
}

func (a *Authenticator) generateCodeVerifier(len int) (string, string) {
	randomBytes := make([]byte, len)
	rand.Read(randomBytes)
	codeVerifier := base64.RawURLEncoding.EncodeToString(randomBytes)[:len]
	h := sha256.New()
	h.Write([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return codeVerifier, codeChallenge
}

// Authenticate with IDP
func (a *Authenticator) Authenticate(ctx context.Context) (payload string, err error) {
	a.done = make(chan error)

	provider, err := oidc.NewProvider(ctx, a.IssuerURL)
	if err != nil {
		return
	}
	oidcConfig := &oidc.Config{
		ClientID: a.ClientID,
	}

	a.tokenVerifier = provider.Verifier(oidcConfig)
	a.oauthConfig = oauth2.Config{
		ClientID:    a.ClientID,
		Endpoint:    provider.Endpoint(),
		RedirectURL: a.RedirectURL,
		Scopes:      []string{oidc.ScopeOpenID, "profile"},
	}

	a.state = a.generateState(64)
	codeVerifier, codeChallenge := a.generateCodeVerifier(128)

	a.codeChallengeParam = oauth2.SetAuthURLParam("code_challenge", codeChallenge)
	a.codeChallengeMethodParam = oauth2.SetAuthURLParam("code_challenge_method", "S256")
	a.codeVerifierParam = oauth2.SetAuthURLParam("code_verifier", codeVerifier)

	u, err := url.Parse(a.RedirectURL)
	if err != nil {
		return
	}

	http.HandleFunc(u.Path, a.callbackHandler)

	listener, err := net.Listen("tcp", a.ListenAddress)
	if err != nil {
		return
	}

	go func() {
		a.done <- http.Serve(listener, nil)
	}()

	go func() {
		if err := browser.OpenURL(a.oauthConfig.AuthCodeURL(a.state, a.codeChallengeParam, a.codeChallengeMethodParam)); err != nil {
			a.done <- err
		}
	}()

	timer := time.NewTimer(a.Timeout)
	for {
		select {
		case <-timer.C:
			err = fmt.Errorf("Timed out after %.fs", a.Timeout.Seconds())
			return
		case err = <-a.done:
			payload = a.payload
			return
		}
	}
}
