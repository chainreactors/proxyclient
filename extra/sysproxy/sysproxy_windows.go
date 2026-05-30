//go:build windows

package sysproxy

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows/registry"
)

const platformName = "windows"

const regPath = `Software\Microsoft\Windows\Internet Settings`

type windowsState struct {
	proxyEnable   uint32
	proxyServer   string
	proxyOverride string
	autoConfigURL string
}

func platformDetect() (*DetectedProxy, error) {
	key, err := registry.OpenKey(registry.CURRENT_USER, regPath, registry.QUERY_VALUE)
	if err != nil {
		return nil, nil
	}
	defer key.Close()

	if regGetDWORD(key, "ProxyEnable") == 0 {
		return nil, nil
	}
	server := regGetString(key, "ProxyServer")
	if server == "" {
		return nil, nil
	}

	bypass := strings.Split(regGetString(key, "ProxyOverride"), ";")
	var bypassList []string
	for _, b := range bypass {
		b = strings.TrimSpace(b)
		if b != "" && b != "<local>" {
			bypassList = append(bypassList, b)
		}
	}

	if strings.HasPrefix(server, "socks=") {
		return &DetectedProxy{Type: ProxySocks, Addr: strings.TrimPrefix(server, "socks="), Bypass: bypassList}, nil
	}
	if idx := strings.Index(server, ";"); idx >= 0 {
		server = server[:idx]
	}
	if strings.Contains(server, "=") {
		parts := strings.SplitN(server, "=", 2)
		server = parts[1]
	}
	return &DetectedProxy{Type: ProxyHTTP, Addr: server, Bypass: bypassList}, nil
}

func platformSet(cfg Config) (any, error) {
	key, err := registry.OpenKey(registry.CURRENT_USER, regPath, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return nil, fmt.Errorf("sysproxy: open registry: %w", err)
	}
	defer key.Close()

	state := &windowsState{
		proxyEnable:   regGetDWORD(key, "ProxyEnable"),
		proxyServer:   regGetString(key, "ProxyServer"),
		proxyOverride: regGetString(key, "ProxyOverride"),
		autoConfigURL: regGetString(key, "AutoConfigURL"),
	}

	if cfg.PACUrl != "" {
		if err := key.SetStringValue("AutoConfigURL", cfg.PACUrl); err != nil {
			return nil, fmt.Errorf("sysproxy: set AutoConfigURL: %w", err)
		}
		key.SetDWordValue("ProxyEnable", 0)
	} else {
		if err := key.SetDWordValue("ProxyEnable", 1); err != nil {
			return nil, fmt.Errorf("sysproxy: set ProxyEnable: %w", err)
		}
		proxyServer := formatWindowsProxy(cfg)
		if err := key.SetStringValue("ProxyServer", proxyServer); err != nil {
			return nil, fmt.Errorf("sysproxy: set ProxyServer: %w", err)
		}
		bypass := strings.Join(cfg.Bypass, ";")
		if bypass != "" {
			bypass += ";<local>"
		} else {
			bypass = "<local>"
		}
		if err := key.SetStringValue("ProxyOverride", bypass); err != nil {
			return nil, fmt.Errorf("sysproxy: set ProxyOverride: %w", err)
		}
		key.DeleteValue("AutoConfigURL")
	}

	notifySettingsChanged()
	return state, nil
}

func platformUnset() error {
	key, err := registry.OpenKey(registry.CURRENT_USER, regPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("sysproxy: open registry: %w", err)
	}
	defer key.Close()

	key.SetDWordValue("ProxyEnable", 0)
	key.DeleteValue("ProxyServer")
	key.DeleteValue("ProxyOverride")
	key.DeleteValue("AutoConfigURL")

	notifySettingsChanged()
	return nil
}

func platformRestore(saved any) error {
	state, ok := saved.(*windowsState)
	if !ok || state == nil {
		return platformUnset()
	}

	key, err := registry.OpenKey(registry.CURRENT_USER, regPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("sysproxy: open registry: %w", err)
	}
	defer key.Close()

	key.SetDWordValue("ProxyEnable", uint32(state.proxyEnable))
	if state.proxyServer != "" {
		key.SetStringValue("ProxyServer", state.proxyServer)
	} else {
		key.DeleteValue("ProxyServer")
	}
	if state.proxyOverride != "" {
		key.SetStringValue("ProxyOverride", state.proxyOverride)
	} else {
		key.DeleteValue("ProxyOverride")
	}
	if state.autoConfigURL != "" {
		key.SetStringValue("AutoConfigURL", state.autoConfigURL)
	} else {
		key.DeleteValue("AutoConfigURL")
	}

	notifySettingsChanged()
	return nil
}

func regGetString(key registry.Key, name string) string {
	v, _, _ := key.GetStringValue(name)
	return v
}

func regGetDWORD(key registry.Key, name string) uint32 {
	v, _, _ := key.GetIntegerValue(name)
	return uint32(v)
}

func formatWindowsProxy(cfg Config) string {
	switch cfg.Type {
	case ProxySocks:
		return "socks=" + cfg.Addr
	default:
		return cfg.Addr
	}
}

func notifySettingsChanged() {
	wininet, err := syscall.LoadDLL("wininet.dll")
	if err != nil {
		return
	}
	defer wininet.Release()

	proc, err := wininet.FindProc("InternetSetOptionW")
	if err != nil {
		return
	}

	const (
		internetOptionSettingsChanged = 39
		internetOptionRefresh         = 37
	)
	proc.Call(0, internetOptionSettingsChanged, 0, 0)
	proc.Call(0, internetOptionRefresh, 0, 0)
	_ = unsafe.Sizeof(0) // ensure unsafe is used
}
