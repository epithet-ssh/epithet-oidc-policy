package main

import (
	"bufio"
	"context"
	"fmt"
	"html/template"
	"io/ioutil"
	"os"
	"time"

	rpc "github.com/epithet-ssh/epithet-oidc/internal/agent"
	"github.com/epithet-ssh/epithet-oidc/pkg/oidc"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var sock = "./control.sock"
var configPath string
var logPath string
var verbosity = 0

// AgentCommand is an agent command
var cmd = &cobra.Command{
	Use:              "epithet-oidc-plugin",
	Short:            "Authentication plugin using OpenID Connect",
	PersistentPreRun: logging,
	RunE:             run,
}

func main() {
	cmd.Flags().CountVarP(&verbosity, "verbose", "v", "how verbose to be, can use multiple")
	cmd.Flags().StringVarP(&sock, "sock", "s", "", "socket to send to")
	cmd.Flags().StringVarP(&configPath, "config", "F", "CONFIG_FILE", "config file to use")
	cmd.Flags().StringVarP(&logPath, "log", "l", "", "path of the log file")
	cmd.MarkFlagRequired("sock")
	cmd.MarkFlagRequired("config")

	err := cmd.Execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func logging(cmd *cobra.Command, args []string) {
	if logPath != "" {
		f, err := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			// Disable file logging when there is an error
			log.SetOutput(ioutil.Discard)
			return
		}
		log.SetOutput(f)
		switch verbosity {
		case 0:
			log.SetLevel(log.WarnLevel)
		case 1:
			log.SetLevel(log.InfoLevel)
		default: // 2+
			log.SetLevel(log.DebugLevel)
		}
	} else {
		log.SetOutput(ioutil.Discard)
	}
}

func run(cc *cobra.Command, args []string) error {
	oidcConfig, err := loadConfigFile(configPath)
	if err != nil {
		return fmt.Errorf("unable to load config %s: %w", configPath, err)
	}

	template, err := template.New("response").Parse(responseTpl)
	if err != nil {
		panic(err)
	}

	ctx := context.Background()

	var refreshToken string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		refreshToken = scanner.Text()
	}

	if err := scanner.Err(); err != nil {
		log.WithError(err).Error("failed to read from stdin")
	}

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
		Template:      template,
	}
	response, err := authenticator.Authenticate(ctx, refreshToken)
	if err != nil {
		return err
	}

	// Pass refresh token to the agent by stdout
	fmt.Fprintf(os.Stdout, response.RefreshToken)

	_, err = client.Authenticate(ctx, &rpc.AuthnRequest{
		Token: response.AccessToken,
	})
	return err
}
