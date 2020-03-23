package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/pkg/browser"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

type templateData struct {
	Username string
	Name     string
	Error    string
}

// Claims - OIDC claims definition
type Claims struct {
	Username string `json:"preferred_username"`
	Name     string `json:"name"`
}

// Authenticator performs OpenID Connect
type Authenticator struct {
	ClientID      string
	IssuerURL     string
	RedirectURL   string
	ListenAddress string
	Timeout       time.Duration
	Template      *template.Template

	token        string
	refreshToken string
	done         chan error

	tokenVerifier            *oidc.IDTokenVerifier
	state                    string
	oauthConfig              oauth2.Config
	codeChallengeParam       oauth2.AuthCodeOption
	codeChallengeMethodParam oauth2.AuthCodeOption
	codeVerifierParam        oauth2.AuthCodeOption
}

func (a *Authenticator) succeeded(w http.ResponseWriter, claims Claims) {
	log.Info("succeeded to authenticate")
	data := templateData{
		Username: claims.Username,
		Name:     claims.Name,
	}
	a.Template.Execute(w, data)
	a.done <- nil
}

func (a *Authenticator) failed(w http.ResponseWriter, err error) {
	log.WithError(err).Error("failed to authenticate")
	data := templateData{
		Error: err.Error(),
	}
	a.Template.Execute(w, data)
	a.done <- err
}

func (a *Authenticator) callbackHandler(w http.ResponseWriter, r *http.Request) {
	log.Info("handling callback")
	if r.URL.Query().Get("state") != a.state {
		a.failed(w, errors.New("state did not match"))
		return
	}

	oauth2Token, err := a.oauthConfig.Exchange(r.Context(), r.URL.Query().Get("code"), a.codeVerifierParam)
	if err != nil {
		a.failed(w, err)
		return
	}
	idToken, err := a.verifyToken(r.Context(), oauth2Token)
	if err != nil {
		a.failed(w, err)
		return
	}

	var claims Claims
	if err = idToken.Claims(&claims); err != nil {
		a.failed(w, fmt.Errorf("Failed to get claims from token: %s", err))
		return
	}

	a.token = oauth2Token.AccessToken
	a.refreshToken = oauth2Token.RefreshToken
	a.succeeded(w, claims)
	return
}

func (a *Authenticator) generateState(len int) string {
	log.Info("generating random state")
	randomBytes := make([]byte, len)
	rand.Read(randomBytes)
	return base64.RawURLEncoding.EncodeToString(randomBytes)[:len]
}

func (a *Authenticator) generateCodeVerifier(len int) (string, string) {
	log.Info("generating code verifier")
	randomBytes := make([]byte, len)
	rand.Read(randomBytes)
	codeVerifier := base64.RawURLEncoding.EncodeToString(randomBytes)[:len]
	h := sha256.New()
	h.Write([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return codeVerifier, codeChallenge
}

func (a *Authenticator) renewToken(ctx context.Context, refreshToken string) (string, error) {
	log.Info("renewing token by refresh token")
	oauthToken := &oauth2.Token{
		RefreshToken: refreshToken,
	}
	tokenSource := a.oauthConfig.TokenSource(ctx, oauthToken)
	newToken, err := tokenSource.Token()
	if err != nil {
		return "", err
	}

	_, err = a.verifyToken(ctx, newToken)
	if err != nil {
		return "", err
	}
	return newToken.AccessToken, nil
}

func (a *Authenticator) verifyToken(ctx context.Context, oauth2Token *oauth2.Token) (*oidc.IDToken, error) {
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("No id_token field in oauth2 token")
	}
	idToken, err := a.tokenVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, err
	}
	err = idToken.VerifyAccessToken(oauth2Token.AccessToken)
	if err != nil {
		return nil, err
	}
	return idToken, nil
}

// Authenticate with IDP
func (a *Authenticator) Authenticate(ctx context.Context, refreshToken string) (string, string, error) {
	a.done = make(chan error)

	provider, err := oidc.NewProvider(ctx, a.IssuerURL)
	if err != nil {
		return "", "", err
	}
	oidcConfig := &oidc.Config{
		ClientID: a.ClientID,
	}

	a.tokenVerifier = provider.Verifier(oidcConfig)
	a.oauthConfig = oauth2.Config{
		ClientID:    a.ClientID,
		Endpoint:    provider.Endpoint(),
		RedirectURL: a.RedirectURL,
		Scopes:      []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess, "profile"},
	}

	// Attempt to renew token by refresh token
	if refreshToken != "" {
		token, err := a.renewToken(ctx, refreshToken)
		if err != nil {
			log.WithError(err).Warn("failed to renew token by refresh token")
		} else {
			return token, refreshToken, err
		}
	}

	log.Info("starting authorization code flow")
	a.state = a.generateState(64)
	codeVerifier, codeChallenge := a.generateCodeVerifier(128)

	a.codeChallengeParam = oauth2.SetAuthURLParam("code_challenge", codeChallenge)
	a.codeChallengeMethodParam = oauth2.SetAuthURLParam("code_challenge_method", "S256")
	a.codeVerifierParam = oauth2.SetAuthURLParam("code_verifier", codeVerifier)

	u, err := url.Parse(a.RedirectURL)
	if err != nil {
		return "", "", err
	}

	http.HandleFunc(u.Path, a.callbackHandler)

	listener, err := net.Listen("tcp", a.ListenAddress)
	if err != nil {
		return "", "", err
	}

	go func() {
		log.Infof("listening on %s to receive callback", a.ListenAddress)
		a.done <- http.Serve(listener, nil)
	}()

	go func() {
		log.Info("opening browser to authenticate")
		if err := browser.OpenURL(a.oauthConfig.AuthCodeURL(a.state, a.codeChallengeParam, a.codeChallengeMethodParam)); err != nil {
			a.done <- err
		}
	}()

	timer := time.NewTimer(a.Timeout)
	for {
		select {
		case <-timer.C:
			return "", "", fmt.Errorf("Timed out after %.fs", a.Timeout.Seconds())
		case err = <-a.done:
			return a.token, a.refreshToken, err
		}
	}
}
