//go:build linux

package sysproxy

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
)

const platformName = "linux"

type desktopEnv int

const (
	desktopGNOME desktopEnv = iota
	desktopKDE
	desktopUnknown
)

type linuxState struct {
	desktop  desktopEnv
	settings map[string]string
}

func detectDesktop() desktopEnv {
	de := strings.ToLower(os.Getenv("XDG_CURRENT_DESKTOP"))
	session := strings.ToLower(os.Getenv("DESKTOP_SESSION"))

	switch {
	case strings.Contains(de, "gnome") || strings.Contains(de, "unity") || strings.Contains(de, "cinnamon") || strings.Contains(de, "mate") || strings.Contains(de, "budgie"):
		if _, err := exec.LookPath("gsettings"); err == nil {
			return desktopGNOME
		}
	case strings.Contains(de, "kde") || strings.Contains(session, "plasma"):
		if _, err := exec.LookPath("kwriteconfig5"); err == nil {
			return desktopKDE
		}
		if _, err := exec.LookPath("kwriteconfig6"); err == nil {
			return desktopKDE
		}
	}

	if _, err := exec.LookPath("gsettings"); err == nil {
		return desktopGNOME
	}

	return desktopUnknown
}

func platformDetect() (*DetectedProxy, error) {
	desktop := detectDesktop()
	switch desktop {
	case desktopGNOME:
		return gnomeDetect()
	case desktopKDE:
		return kdeDetect()
	default:
		return envDetect()
	}
}

func gnomeDetect() (*DetectedProxy, error) {
	mode := gnomeGet("org.gnome.system.proxy", "mode")
	if mode != "manual" {
		return nil, nil
	}
	if host := gnomeGet("org.gnome.system.proxy.socks", "host"); host != "" {
		port := gnomeGet("org.gnome.system.proxy.socks", "port")
		if port != "" && port != "0" {
			return &DetectedProxy{Type: ProxySocks, Addr: host + ":" + port}, nil
		}
	}
	if host := gnomeGet("org.gnome.system.proxy.http", "host"); host != "" {
		port := gnomeGet("org.gnome.system.proxy.http", "port")
		if port != "" && port != "0" {
			return &DetectedProxy{Type: ProxyHTTP, Addr: host + ":" + port}, nil
		}
	}
	return nil, nil
}

func kdeDetect() (*DetectedProxy, error) {
	proxyType := kdeGet("Proxy Settings", "ProxyType")
	if proxyType != "1" {
		return nil, nil
	}
	if socks := kdeGet("Proxy Settings", "socksProxy"); socks != "" {
		addr := strings.TrimPrefix(socks, "http://")
		addr = strings.TrimPrefix(addr, "socks://")
		return &DetectedProxy{Type: ProxySocks, Addr: addr}, nil
	}
	if hp := kdeGet("Proxy Settings", "httpProxy"); hp != "" {
		addr := strings.TrimPrefix(hp, "http://")
		return &DetectedProxy{Type: ProxyHTTP, Addr: addr}, nil
	}
	return nil, nil
}

func envDetect() (*DetectedProxy, error) {
	for _, key := range []string{"https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY"} {
		if v := os.Getenv(key); v != "" {
			return parseEnvProxy(v)
		}
	}
	for _, key := range []string{"all_proxy", "ALL_PROXY"} {
		if v := os.Getenv(key); v != "" {
			return parseEnvProxy(v)
		}
	}
	return nil, nil
}

func parseEnvProxy(raw string) (*DetectedProxy, error) {
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, nil
	}
	addr := u.Host
	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks", "socks5h":
		return &DetectedProxy{Type: ProxySocks, Addr: addr}, nil
	default:
		return &DetectedProxy{Type: ProxyHTTP, Addr: addr}, nil
	}
}

func platformSet(cfg Config) (any, error) {
	desktop := detectDesktop()

	switch desktop {
	case desktopGNOME:
		return gnomeSet(cfg)
	case desktopKDE:
		return kdeSet(cfg)
	default:
		return nil, fmt.Errorf("sysproxy: unsupported Linux desktop environment (need GNOME/KDE with gsettings/kwriteconfig)")
	}
}

func platformUnset() error {
	desktop := detectDesktop()
	switch desktop {
	case desktopGNOME:
		return gnomeUnset()
	case desktopKDE:
		return kdeUnset()
	default:
		return fmt.Errorf("sysproxy: unsupported Linux desktop environment")
	}
}

func platformRestore(saved any) error {
	state, ok := saved.(*linuxState)
	if !ok || state == nil {
		return platformUnset()
	}

	switch state.desktop {
	case desktopGNOME:
		return gnomeRestore(state)
	case desktopKDE:
		return kdeRestore(state)
	default:
		return platformUnset()
	}
}

// GNOME (gsettings)

func gnomeGet(schema, key string) string {
	out, err := exec.Command("gsettings", "get", schema, key).Output()
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(out))
	s = strings.Trim(s, "'\"")
	return s
}

func gnomeSetVal(schema, key, val string) error {
	return exec.Command("gsettings", "set", schema, key, val).Run()
}

func gnomeSet(cfg Config) (any, error) {
	state := &linuxState{
		desktop:  desktopGNOME,
		settings: make(map[string]string),
	}

	state.settings["mode"] = gnomeGet("org.gnome.system.proxy", "mode")
	state.settings["http.host"] = gnomeGet("org.gnome.system.proxy.http", "host")
	state.settings["http.port"] = gnomeGet("org.gnome.system.proxy.http", "port")
	state.settings["https.host"] = gnomeGet("org.gnome.system.proxy.https", "host")
	state.settings["https.port"] = gnomeGet("org.gnome.system.proxy.https", "port")
	state.settings["socks.host"] = gnomeGet("org.gnome.system.proxy.socks", "host")
	state.settings["socks.port"] = gnomeGet("org.gnome.system.proxy.socks", "port")
	state.settings["ignore-hosts"] = gnomeGet("org.gnome.system.proxy", "ignore-hosts")
	state.settings["autoconfig-url"] = gnomeGet("org.gnome.system.proxy", "autoconfig-url")

	if cfg.PACUrl != "" {
		gnomeSetVal("org.gnome.system.proxy", "mode", "'auto'")
		gnomeSetVal("org.gnome.system.proxy", "autoconfig-url", "'"+cfg.PACUrl+"'")
		return state, nil
	}

	gnomeSetVal("org.gnome.system.proxy", "mode", "'manual'")

	host, port := splitHostPort(cfg.Addr)

	switch cfg.Type {
	case ProxySocks:
		gnomeSetVal("org.gnome.system.proxy.socks", "host", "'"+host+"'")
		gnomeSetVal("org.gnome.system.proxy.socks", "port", port)
	default:
		gnomeSetVal("org.gnome.system.proxy.http", "host", "'"+host+"'")
		gnomeSetVal("org.gnome.system.proxy.http", "port", port)
		gnomeSetVal("org.gnome.system.proxy.https", "host", "'"+host+"'")
		gnomeSetVal("org.gnome.system.proxy.https", "port", port)
	}

	if len(cfg.Bypass) > 0 {
		hosts := make([]string, len(cfg.Bypass))
		for i, h := range cfg.Bypass {
			hosts[i] = "'" + h + "'"
		}
		gnomeSetVal("org.gnome.system.proxy", "ignore-hosts", "["+strings.Join(hosts, ", ")+"]")
	}

	return state, nil
}

func gnomeUnset() error {
	return gnomeSetVal("org.gnome.system.proxy", "mode", "'none'")
}

func gnomeRestore(state *linuxState) error {
	if mode, ok := state.settings["mode"]; ok && mode != "" {
		gnomeSetVal("org.gnome.system.proxy", "mode", "'"+mode+"'")
	} else {
		gnomeSetVal("org.gnome.system.proxy", "mode", "'none'")
	}

	restorePairs := []struct{ schema, key, stateKey string }{
		{"org.gnome.system.proxy.http", "host", "http.host"},
		{"org.gnome.system.proxy.http", "port", "http.port"},
		{"org.gnome.system.proxy.https", "host", "https.host"},
		{"org.gnome.system.proxy.https", "port", "https.port"},
		{"org.gnome.system.proxy.socks", "host", "socks.host"},
		{"org.gnome.system.proxy.socks", "port", "socks.port"},
	}
	for _, p := range restorePairs {
		if val, ok := state.settings[p.stateKey]; ok && val != "" {
			if p.key == "port" {
				gnomeSetVal(p.schema, p.key, val)
			} else {
				gnomeSetVal(p.schema, p.key, "'"+val+"'")
			}
		}
	}

	if hosts, ok := state.settings["ignore-hosts"]; ok && hosts != "" {
		gnomeSetVal("org.gnome.system.proxy", "ignore-hosts", hosts)
	}
	if acURL, ok := state.settings["autoconfig-url"]; ok && acURL != "" {
		gnomeSetVal("org.gnome.system.proxy", "autoconfig-url", "'"+acURL+"'")
	}

	return nil
}

// KDE (kwriteconfig5/kwriteconfig6)

func kdeCmd() string {
	if _, err := exec.LookPath("kwriteconfig6"); err == nil {
		return "kwriteconfig6"
	}
	return "kwriteconfig5"
}

func kdeReadCmd() string {
	if _, err := exec.LookPath("kreadconfig6"); err == nil {
		return "kreadconfig6"
	}
	return "kreadconfig5"
}

func kdeGet(group, key string) string {
	out, err := exec.Command(kdeReadCmd(), "--file", "kioslaverc", "--group", group, "--key", key).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func kdeSetVal(group, key, val string) error {
	return exec.Command(kdeCmd(), "--file", "kioslaverc", "--group", group, "--key", key, val).Run()
}

func kdeSet(cfg Config) (any, error) {
	state := &linuxState{
		desktop:  desktopKDE,
		settings: make(map[string]string),
	}

	state.settings["ProxyType"] = kdeGet("Proxy Settings", "ProxyType")
	state.settings["httpProxy"] = kdeGet("Proxy Settings", "httpProxy")
	state.settings["httpsProxy"] = kdeGet("Proxy Settings", "httpsProxy")
	state.settings["socksProxy"] = kdeGet("Proxy Settings", "socksProxy")
	state.settings["NoProxyFor"] = kdeGet("Proxy Settings", "NoProxyFor")
	state.settings["Proxy Config Script"] = kdeGet("Proxy Settings", "Proxy Config Script")

	if cfg.PACUrl != "" {
		kdeSetVal("Proxy Settings", "ProxyType", "2")
		kdeSetVal("Proxy Settings", "Proxy Config Script", cfg.PACUrl)
		return state, nil
	}

	kdeSetVal("Proxy Settings", "ProxyType", "1")

	proxyURL := fmt.Sprintf("http://%s", cfg.Addr)

	switch cfg.Type {
	case ProxySocks:
		kdeSetVal("Proxy Settings", "socksProxy", proxyURL)
	default:
		kdeSetVal("Proxy Settings", "httpProxy", proxyURL)
		kdeSetVal("Proxy Settings", "httpsProxy", proxyURL)
	}

	if len(cfg.Bypass) > 0 {
		kdeSetVal("Proxy Settings", "NoProxyFor", strings.Join(cfg.Bypass, ","))
	}

	return state, nil
}

func kdeUnset() error {
	return kdeSetVal("Proxy Settings", "ProxyType", "0")
}

func kdeRestore(state *linuxState) error {
	for key, val := range state.settings {
		if val != "" {
			kdeSetVal("Proxy Settings", key, val)
		}
	}
	return nil
}

func splitHostPort(addr string) (string, string) {
	if idx := strings.LastIndex(addr, ":"); idx >= 0 {
		return addr[:idx], addr[idx+1:]
	}
	return addr, "0"
}
