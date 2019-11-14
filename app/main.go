package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
)

// AuthMiddleware handles authentication
type AuthMiddleware struct {
	Authenticator *Authenticator
	JwksURL       string
	Issuer        string
	Audience      []string
}

// Init the middleware
func (a *AuthMiddleware) Init() error {
	a.Authenticator = &Authenticator{
		JwksURL:  a.JwksURL,
		Issuer:   a.Issuer,
		Audience: a.Audience,
	}
	err := a.Authenticator.GetJWKS()
	if err != nil {
		return err
	}

	return nil
}

// Middleware function, which will be called for each request
func (a *AuthMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		user, groups, err := a.Authenticator.Authenticate(token)
		if err != nil {
			http.Error(w, "Forbidden", http.StatusForbidden)
		} else {
			context.Set(r, "user", user)
			context.Set(r, "groups", groups)
			next.ServeHTTP(w, r)
		}
	})
}

func CertParamsHandler(w http.ResponseWriter, r *http.Request) {
	certParams := ca.CertParams{
		Identity:   context.Get(r, "user").(string),
		Names:      context.Get(r, "groups").([]string),
		Expiration: time.Minute,
		Extensions: map[string]string{
			"permit-agent-forwarding": "",
			"permit-pty":              "",
			"permit-user-rc":          "",
		},
	}
	bytes, err := json.Marshal(certParams)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(bytes)
}

func main() {
	authMiddleware := AuthMiddleware{
		JwksURL: "https://dev-585900.okta.com/oauth2/default/v1/keys",
		Issuer:  "https://dev-585900.okta.com/oauth2/default",
		Audience: []string{
			"0oa1owuye8JlLeWG1357",
		},
	}
	err := authMiddleware.Init()
	if err != nil {
		log.Fatal(err)
		return
	}

	r := mux.NewRouter()
	r.HandleFunc("/", CertParamsHandler)
	r.Use(authMiddleware.Middleware)
	log.Fatal(http.ListenAndServe(":9999", r))
}
