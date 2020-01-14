package main

import (
	"context"
	"fmt"
	"os"
	"time"

	rpc "github.com/epithet-ssh/epithet-oidc/internal/agent"
	"github.com/epithet-ssh/epithet-oidc/pkg/oidc"
	"github.com/spf13/cobra"
)

var sock = "./control.sock"
var configPath string

// AgentCommand is an agent command
var cmd = &cobra.Command{
	Use:   "epithet-oidc",
	Short: "Authentication plugin using OpenID Connect",
	RunE:  run,
}

func main() {
	cmd.Flags().StringVarP(&sock, "sock", "s", "", "socket to send to")
	cmd.Flags().StringVarP(&configPath, "config", "F", "CONFIG_FILE", "config file to use")
	cmd.MarkFlagRequired("sock")
	cmd.MarkFlagRequired("config")

	err := cmd.Execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(cc *cobra.Command, args []string) error {
	oidcConfig, err := loadConfigFile(configPath)
	if err != nil {
		return fmt.Errorf("unable to load config %s: %w", configPath, err)
	}

	ctx := context.Background()

	client, err := rpc.NewClient(sock)
	if err != nil {
		return err
	}
	authenticator := oidc.Authenticator{
		ClientID:      oidcConfig.ClientID,
		IssuerURL:     oidcConfig.IssuerURL,
		RedirectURL:   oidcConfig.RedirectURL,
		ListenAddress: oidcConfig.ListenAddress,
		Timeout:       time.Duration(oidcConfig.Timeout) * time.Second,
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
