package sysproxy

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

type PACConfig struct {
	ProxyAddr     string
	DirectDomains []string
	ProxyDomains  []string
}

func GeneratePAC(cfg PACConfig) string {
	var b strings.Builder
	b.WriteString("function FindProxyForURL(url, host) {\n")

	b.WriteString("  if (isPlainHostName(host)) return \"DIRECT\";\n")

	for _, d := range cfg.DirectDomains {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if strings.Contains(d, "/") {
			ip, mask := parseCIDR(d)
			if ip != "" {
				fmt.Fprintf(&b, "  if (isInNet(host, %q, %q)) return \"DIRECT\";\n", ip, mask)
				continue
			}
		}
		if strings.HasPrefix(d, "*.") {
			fmt.Fprintf(&b, "  if (dnsDomainIs(host, %q)) return \"DIRECT\";\n", d[1:])
		} else {
			fmt.Fprintf(&b, "  if (host == %q || dnsDomainIs(host, %q)) return \"DIRECT\";\n", d, "."+d)
		}
	}

	if len(cfg.ProxyDomains) > 0 {
		for _, d := range cfg.ProxyDomains {
			d = strings.TrimSpace(d)
			if d == "" {
				continue
			}
			if strings.HasPrefix(d, "*.") {
				fmt.Fprintf(&b, "  if (dnsDomainIs(host, %q)) return %q;\n", d[1:], cfg.ProxyAddr)
			} else {
				fmt.Fprintf(&b, "  if (host == %q || dnsDomainIs(host, %q)) return %q;\n", d, "."+d, cfg.ProxyAddr)
			}
		}
		b.WriteString("  return \"DIRECT\";\n")
	} else {
		fmt.Fprintf(&b, "  return %q;\n", cfg.ProxyAddr)
	}

	b.WriteString("}\n")
	return b.String()
}

func ServePAC(listenAddr string, cfg PACConfig) (pacURL string, stop func(), err error) {
	content := GeneratePAC(cfg)

	mux := http.NewServeMux()
	mux.HandleFunc("/proxy.pac", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
		w.Write([]byte(content))
	})

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return "", nil, fmt.Errorf("sysproxy: listen PAC server: %w", err)
	}

	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)

	addr := ln.Addr().(*net.TCPAddr)
	host := addr.IP.String()
	if host == "::" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	pacURL = fmt.Sprintf("http://%s:%d/proxy.pac", host, addr.Port)

	stop = func() {
		srv.Close()
	}

	return pacURL, stop, nil
}

func parseCIDR(cidr string) (ip, mask string) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", ""
	}
	return ipNet.IP.String(), net.IP(ipNet.Mask).String()
}
