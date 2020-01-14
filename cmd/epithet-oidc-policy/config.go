package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
	"path/filepath"

	"github.com/naoina/toml"
	"gopkg.in/yaml.v2"
)

type unmarshal func([]byte, interface{}) error

func loadConfigFile(path string) (*config, error) {
	body, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("unable to load config file: %w", err)
	}

	ext := filepath.Ext(path)
	switch ext {
	case ".yaml":
		return parse(yaml.Unmarshal, body)
	case ".yml":
		return parse(yaml.Unmarshal, body)
	case ".toml":
		return parse(toml.Unmarshal, body)
	case ".json":
		return parse(json.Unmarshal, body)
	default:
		return nil, fmt.Errorf("unknown config file type '%s'", ext)
	}
}

func parse(un unmarshal, body []byte) (*config, error) {
	cfg := config{}

	if err := un(body, &cfg); err != nil {
		return nil, err
	}

	cfg.init()

	return &cfg, nil
}

type config struct {
	JwksURL           string   `json:"jwks_url" yaml:"jwks_url" toml:"jwks_url"`
	Issuer            string   `json:"issuer" yaml:"issuer" toml:"issuer"`
	Audience          []string `json:"audience" yaml:"audience" toml:"audience"`
	AuthorizerCommand string   `json:"authorizer_command" yaml:"authorizer_command" toml:"authorizer_command"`
}

func (c *config) init() error {
	_, err := url.Parse(c.JwksURL)
	if err != nil {
		return fmt.Errorf("invalid jwks_url: %w", err)
	}

	return nil
}
