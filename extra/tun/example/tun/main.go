package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/chainreactors/proxyclient"
	"github.com/chainreactors/proxyclient/extra/tun"
)

func main() {
	var (
		proxyURLs   proxyURLList
		name        string
		stack       string
		mtu         uint
		inet4CSV    string
		inet6CSV    string
		autoRoute   bool
		strictRoute bool
		udpTimeout  time.Duration
	)
	flag.Var(&proxyURLs, "proxy", "proxy URL; repeat to build a proxy chain, e.g. -proxy socks5://127.0.0.1:1080 -proxy http://127.0.0.1:8080")
	flag.StringVar(&name, "name", "", "tun interface name")
	flag.StringVar(&stack, "stack", tun.DefaultStack, "sing-tun stack: gvisor, mixed, or system")
	flag.UintVar(&mtu, "mtu", uint(tun.DefaultMTU), "tun MTU")
	flag.StringVar(&inet4CSV, "inet4", tun.DefaultInet4Prefix.String(), "comma-separated IPv4 interface prefixes")
	flag.StringVar(&inet6CSV, "inet6", "", "comma-separated IPv6 interface prefixes")
	flag.BoolVar(&autoRoute, "auto-route", false, "let sing-tun manage routes")
	flag.BoolVar(&strictRoute, "strict-route", false, "enable sing-tun strict route mode")
	flag.DurationVar(&udpTimeout, "udp-timeout", tun.DefaultUDPTimeout, "UDP session timeout")
	flag.Parse()

	if len(proxyURLs) == 0 {
		fmt.Fprintf(os.Stderr, "missing --proxy\n")
		flag.Usage()
		os.Exit(2)
	}
	dial, dialerLabel, err := newProxyDialer(proxyURLs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create proxy dialer: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	svc, err := tun.Start(ctx, dial, tun.Options{
		Name:        name,
		Stack:       stack,
		MTU:         uint32(mtu),
		Inet4:       mustParsePrefixes("inet4", inet4CSV),
		Inet6:       mustParsePrefixes("inet6", inet6CSV),
		AutoRoute:   autoRoute,
		StrictRoute: strictRoute,
		UDPTimeout:  udpTimeout,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "start tun: %v\n", err)
		os.Exit(1)
	}
	defer svc.Close()

	tunName, _ := svc.Name()
	fmt.Printf("tun started on %s via %s\n", tunName, dialerLabel)
	<-ctx.Done()
}

func newProxyDialer(proxyURLs proxyURLList) (proxyclient.Dial, string, error) {
	proxies := make([]*url.URL, 0, len(proxyURLs))
	labels := make([]string, 0, len(proxyURLs))
	for _, value := range proxyURLs {
		parsedProxy, err := url.Parse(value)
		if err != nil {
			return nil, "", fmt.Errorf("parse proxy URL %q: %w", value, err)
		}
		proxies = append(proxies, parsedProxy)
		labels = append(labels, parsedProxy.Redacted())
	}
	if len(proxies) == 0 {
		return nil, "", errors.New("missing proxy URL")
	}
	if len(proxies) == 1 {
		dial, err := proxyclient.NewClient(proxies[0])
		return dial, labels[0], err
	}
	dial, err := proxyclient.NewClientChain(proxies)
	return dial, strings.Join(labels, " -> "), err
}

func mustParsePrefixes(name string, value string) []netip.Prefix {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	prefixes := make([]netip.Prefix, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(part)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid --%s prefix %q: %v\n", name, part, err)
			os.Exit(2)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes
}

type proxyURLList []string

func (l *proxyURLList) String() string {
	if l == nil {
		return ""
	}
	return strings.Join(*l, ",")
}

func (l *proxyURLList) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("proxy URL is empty")
	}
	*l = append(*l, value)
	return nil
}
