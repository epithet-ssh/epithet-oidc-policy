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
	verifier := provider.Verifier(oidcConfig)
	config := oauth2.Config{
		ClientID:    a.ClientID,
		Endpoint:    provider.Endpoint(),
		RedirectURL: a.RedirectURL,
		Scopes:      []string{oidc.ScopeOpenID, "profile"},
	}

	// Generate random state
	randomBytes := make([]byte, 64)
	rand.Read(randomBytes)
	state := base64.RawURLEncoding.EncodeToString(randomBytes)[:64]

	// Generate PKCE verifier and challenge
	randomBytes = make([]byte, 128)
	rand.Read(randomBytes)
	codeVerifier := base64.RawURLEncoding.EncodeToString(randomBytes)[:128]
	h := sha256.New()
	h.Write([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	codeChallengeParam := oauth2.SetAuthURLParam("code_challenge", codeChallenge)
	codeChallengeMethodParam := oauth2.SetAuthURLParam("code_challenge_method", "S256")
	codeVerifierParam := oauth2.SetAuthURLParam("code_verifier", codeVerifier)

	u, err := url.Parse(a.RedirectURL)
	if err != nil {
		return
	}

	http.HandleFunc(u.Path, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			a.failed(w, errors.New("state did not match"))
			return
		}

		oauth2Token, err := config.Exchange(ctx, r.URL.Query().Get("code"), codeVerifierParam)
		if err != nil {
			a.failed(w, err)
			return
		}
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			a.failed(w, errors.New("No id_token field in oauth2 token"))
			return
		}
		_, err = verifier.Verify(ctx, rawIDToken)
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
	})

	listener, err := net.Listen("tcp", a.ListenAddress)
	if err != nil {
		return
	}

	go func() {
		a.done <- http.Serve(listener, nil)
	}()

	go func() {
		if err := browser.OpenURL(config.AuthCodeURL(state, codeChallengeParam, codeChallengeMethodParam)); err != nil {
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
