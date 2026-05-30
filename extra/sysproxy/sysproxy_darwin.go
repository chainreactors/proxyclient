//go:build darwin

package sysproxy

import (
	"fmt"
	"os/exec"
	"strings"
)

const platformName = "darwin"

type darwinServiceState struct {
	service     string
	webProxy    string
	socksProxy  string
	webEnabled  bool
	socksEnabled bool
	bypass      string
	autoProxyURL string
}

type darwinState struct {
	services []darwinServiceState
}

func platformDetect() (*DetectedProxy, error) {
	services, err := listNetworkServices()
	if err != nil {
		return nil, nil
	}
	for _, svc := range services {
		if addr, enabled := getProxy(svc, "socksfirewallproxy"); enabled && addr != "" {
			return &DetectedProxy{Type: ProxySocks, Addr: addr}, nil
		}
		if addr, enabled := getProxy(svc, "webproxy"); enabled && addr != "" {
			return &DetectedProxy{Type: ProxyHTTP, Addr: addr}, nil
		}
	}
	return nil, nil
}

func platformSet(cfg Config) (any, error) {
	services, err := listNetworkServices()
	if err != nil {
		return nil, err
	}

	state := &darwinState{}
	var errs []string

	for _, svc := range services {
		svcState := darwinServiceState{service: svc}
		svcState.webProxy, svcState.webEnabled = getProxy(svc, "webproxy")
		svcState.socksProxy, svcState.socksEnabled = getProxy(svc, "socksfirewallproxy")
		svcState.bypass = getBypass(svc)
		svcState.autoProxyURL = getAutoProxy(svc)
		state.services = append(state.services, svcState)

		if err := applyConfig(svc, cfg); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", svc, err))
		}
	}

	if len(errs) > 0 {
		return state, fmt.Errorf("sysproxy: partial failure: %s", strings.Join(errs, "; "))
	}
	return state, nil
}

func platformUnset() error {
	services, err := listNetworkServices()
	if err != nil {
		return err
	}
	for _, svc := range services {
		networksetup("-setwebproxystate", svc, "off")
		networksetup("-setsocksfirewallproxystate", svc, "off")
		networksetup("-setautoproxystate", svc, "off")
	}
	return nil
}

func platformRestore(saved any) error {
	state, ok := saved.(*darwinState)
	if !ok || state == nil {
		return platformUnset()
	}

	var errs []string
	for _, svc := range state.services {
		if svc.webEnabled {
			parts := strings.SplitN(svc.webProxy, ":", 2)
			if len(parts) == 2 {
				networksetup("-setwebproxy", svc.service, parts[0], parts[1])
				networksetup("-setwebproxystate", svc.service, "on")
			}
		} else {
			networksetup("-setwebproxystate", svc.service, "off")
		}

		if svc.socksEnabled {
			parts := strings.SplitN(svc.socksProxy, ":", 2)
			if len(parts) == 2 {
				networksetup("-setsocksfirewallproxy", svc.service, parts[0], parts[1])
				networksetup("-setsocksfirewallproxystate", svc.service, "on")
			}
		} else {
			networksetup("-setsocksfirewallproxystate", svc.service, "off")
		}

		if svc.autoProxyURL != "" {
			networksetup("-setautoproxyurl", svc.service, svc.autoProxyURL)
			networksetup("-setautoproxystate", svc.service, "on")
		} else {
			networksetup("-setautoproxystate", svc.service, "off")
		}

		if svc.bypass != "" {
			args := append([]string{"-setproxybypassdomains", svc.service}, strings.Fields(svc.bypass)...)
			networksetup(args...)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("sysproxy: partial restore failure: %s", strings.Join(errs, "; "))
	}
	return nil
}

func applyConfig(service string, cfg Config) error {
	host, port := splitHostPort(cfg.Addr)

	if cfg.PACUrl != "" {
		networksetup("-setwebproxystate", service, "off")
		networksetup("-setsocksfirewallproxystate", service, "off")
		if _, err := networksetup("-setautoproxyurl", service, cfg.PACUrl); err != nil {
			return err
		}
		_, err := networksetup("-setautoproxystate", service, "on")
		return err
	}

	networksetup("-setautoproxystate", service, "off")

	switch cfg.Type {
	case ProxySocks:
		networksetup("-setwebproxystate", service, "off")
		if _, err := networksetup("-setsocksfirewallproxy", service, host, port); err != nil {
			return err
		}
		_, err := networksetup("-setsocksfirewallproxystate", service, "on")
		if err != nil {
			return err
		}
	default:
		networksetup("-setsocksfirewallproxystate", service, "off")
		if _, err := networksetup("-setwebproxy", service, host, port); err != nil {
			return err
		}
		if _, err := networksetup("-setsecurewebproxy", service, host, port); err != nil {
			return err
		}
		if _, err := networksetup("-setwebproxystate", service, "on"); err != nil {
			return err
		}
		_, err := networksetup("-setsecurewebproxystate", service, "on")
		if err != nil {
			return err
		}
	}

	if len(cfg.Bypass) > 0 {
		args := append([]string{"-setproxybypassdomains", service}, cfg.Bypass...)
		networksetup(args...)
	}
	return nil
}

func listNetworkServices() ([]string, error) {
	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil, fmt.Errorf("sysproxy: listallnetworkservices: %w", err)
	}
	var services []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "*") || strings.Contains(line, "denotes") {
			continue
		}
		services = append(services, line)
	}
	return services, nil
}

func networksetup(args ...string) (string, error) {
	out, err := exec.Command("networksetup", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func getProxy(service, proxyType string) (string, bool) {
	out, err := networksetup("-get"+proxyType, service)
	if err != nil {
		return "", false
	}
	var host, port string
	var enabled bool
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Server:") {
			host = strings.TrimSpace(strings.TrimPrefix(line, "Server:"))
		} else if strings.HasPrefix(line, "Port:") {
			port = strings.TrimSpace(strings.TrimPrefix(line, "Port:"))
		} else if strings.HasPrefix(line, "Enabled:") {
			enabled = strings.TrimSpace(strings.TrimPrefix(line, "Enabled:")) == "Yes"
		}
	}
	if host == "" || port == "" || port == "0" {
		return "", false
	}
	return host + ":" + port, enabled
}

func getBypass(service string) string {
	out, err := networksetup("-getproxybypassdomains", service)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

func getAutoProxy(service string) string {
	out, err := networksetup("-getautoproxyurl", service)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "URL:") {
			u := strings.TrimSpace(strings.TrimPrefix(line, "URL:"))
			if u != "(null)" && u != "" {
				return u
			}
		}
	}
	return ""
}

func splitHostPort(addr string) (string, string) {
	if idx := strings.LastIndex(addr, ":"); idx >= 0 {
		return addr[:idx], addr[idx+1:]
	}
	return addr, "0"
}
