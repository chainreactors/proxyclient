package sysproxy

import (
	"fmt"
	"net/url"
)

type ProxyType int

const (
	ProxyHTTP  ProxyType = iota
	ProxySocks
)

type Config struct {
	Type   ProxyType
	Addr   string
	Bypass []string
	PACUrl string
}

func (c Config) validate() error {
	if c.PACUrl != "" {
		return nil
	}
	if c.Addr == "" {
		return fmt.Errorf("sysproxy: addr is required when PACUrl is not set")
	}
	return nil
}

type State struct {
	platform string
	saved    any
}

func Set(cfg Config) (*State, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	saved, err := platformSet(cfg)
	if err != nil {
		return nil, err
	}
	return &State{platform: platformName, saved: saved}, nil
}

func Unset() error {
	return platformUnset()
}

func Restore(state *State) error {
	if state == nil {
		return nil
	}
	return platformRestore(state.saved)
}

// DetectedProxy represents the system's current proxy configuration.
type DetectedProxy struct {
	Type   ProxyType
	Addr   string
	Bypass []string
}

// Detect reads the current system proxy configuration.
// Returns nil if no system proxy is configured.
func Detect() (*DetectedProxy, error) {
	return platformDetect()
}

// URL converts the detected proxy to a proxyclient-compatible URL.
func (d *DetectedProxy) URL() *url.URL {
	switch d.Type {
	case ProxySocks:
		return &url.URL{Scheme: "socks5", Host: d.Addr}
	default:
		return &url.URL{Scheme: "http", Host: d.Addr}
	}
}
