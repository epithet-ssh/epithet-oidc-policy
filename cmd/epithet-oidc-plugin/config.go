package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
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
	oidcConfig := &config{}

	if err := un(body, &oidcConfig); err != nil {
		return nil, err
	}

	return oidcConfig, nil
}

type config struct {
	ClientID      string `json:"client_id" yaml:"client_id" toml:"client_id"`
	IssuerURL     string `json:"issuer_url" yaml:"issuer_url" toml:"issuer_url"`
	RedirectURL   string `json:"redirect_url" yaml:"redirect_url" toml:"redirect_url"`
	ListenAddress string `json:"listen_address" yaml:"listen_address" toml:"listen_address"`
	Timeout       int    `json:"timeout" yaml:"timeout" toml:"timeout"`
}
