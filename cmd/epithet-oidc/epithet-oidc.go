package main

import (
	"context"
	"fmt"
	"os"
	"time"

	rpc "github.com/micbase/epithet-oidc-plugin/internal/agent"
	"github.com/micbase/epithet-oidc-plugin/pkg/oidc"
	"github.com/spf13/cobra"
)

var sock = "./control.sock"

// AgentCommand is an agent command
var cmd = &cobra.Command{
	Use:   "epithet-auth",
	Short: "Submit authentication requests to the agent",
	RunE:  run,
}

func main() {
	cmd.Flags().StringVarP(&sock, "sock", "s", sock, "socket to send to")

	err := cmd.Execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(cc *cobra.Command, args []string) error {
	ctx := context.Background()

	client, err := rpc.NewClient(sock)
	if err != nil {
		return err
	}
	authenticator := oidc.Authenticator{
		ClientID:      "0oa1owuye8JlLeWG1357",
		IssuerURL:     "https://dev-585900.okta.com/oauth2/default",
		RedirectURL:   "http://127.0.0.1:5555/callback",
		ListenAddress: "127.0.0.1:5555",
		Timeout:       60 * time.Second,
	}
	payload, err := authenticator.Authenticate(ctx)
	if err != nil {
		return err
	}

	_, err = client.Authenticate(ctx, &rpc.AuthnRequest{
		Token: payload,
	})
	return err
}
