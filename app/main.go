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

// AuthticationMiddleware handles authentication
type AuthticationMiddleware struct {
	Authenticator *Authenticator
	JwksURL       string
	Issuer        string
	Audience      []string
}

// Init the middleware
func (a *AuthticationMiddleware) Init() error {
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
func (a *AuthticationMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		user, err := a.Authenticator.Authenticate(token)
		if err != nil {
			http.Error(w, "Forbidden", http.StatusForbidden)
		} else {
			context.Set(r, "user", user)
			next.ServeHTTP(w, r)
		}
	})
}

// AuthorizationMiddleware handles authorization
type AuthorizationMiddleware struct {
}

// Init the middleware
func (a *AuthorizationMiddleware) Init() error {
	return nil
}

// Middleware function, which will be called for each request
func (a *AuthorizationMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		groups := []string{
			"group2",
		}
		expiration := 120
		extensions := map[string]string{
			"permit-agent-forwarding": "",
			"permit-pty":              "",
			"permit-user-rc":          "",
		}

		context.Set(r, "groups", groups)
		context.Set(r, "expiration", expiration)
		context.Set(r, "extensions", extensions)
		next.ServeHTTP(w, r)
	})
}

// CertParamsHandler generates SSH cert parameters
func CertParamsHandler(w http.ResponseWriter, r *http.Request) {
	certParams := ca.CertParams{
		Identity:   context.Get(r, "user").(string),
		Names:      context.Get(r, "groups").([]string),
		Expiration: time.Duration(context.Get(r, "expiration").(int)) * time.Second,
		Extensions: context.Get(r, "extensions").(map[string]string),
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
	authticationMiddleware := AuthticationMiddleware{
		JwksURL: "https://dev-585900.okta.com/oauth2/default/v1/keys",
		Issuer:  "https://dev-585900.okta.com/oauth2/default",
		Audience: []string{
			"0oa1owuye8JlLeWG1357",
		},
	}
	err := authticationMiddleware.Init()
	if err != nil {
		log.Fatal(err)
		return
	}

	authorizationMiddleware := AuthorizationMiddleware{}
	err = authorizationMiddleware.Init()
	if err != nil {
		log.Fatal(err)
		return
	}

	r := mux.NewRouter()
	r.Use(authticationMiddleware.Middleware)
	r.Use(authorizationMiddleware.Middleware)
	r.HandleFunc("/", CertParamsHandler).Methods("GET")
	log.Fatal(http.ListenAndServe(":9999", r))
}
