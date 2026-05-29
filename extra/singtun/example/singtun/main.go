package main

import (
	"context"
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
	"github.com/chainreactors/proxyclient/extra/singtun"
)

func main() {
	var (
		proxyURL    string
		name        string
		stack       string
		mtu         uint
		inet4CSV    string
		inet6CSV    string
		autoRoute   bool
		strictRoute bool
		udpTimeout  time.Duration
	)
	flag.StringVar(&proxyURL, "proxy", "", "proxy URL, e.g. socks5://127.0.0.1:1080")
	flag.StringVar(&name, "name", "", "tun interface name")
	flag.StringVar(&stack, "stack", singtun.DefaultStack, "sing-tun stack: gvisor, mixed, or system")
	flag.UintVar(&mtu, "mtu", uint(singtun.DefaultMTU), "tun MTU")
	flag.StringVar(&inet4CSV, "inet4", singtun.DefaultInet4Prefix.String(), "comma-separated IPv4 interface prefixes")
	flag.StringVar(&inet6CSV, "inet6", "", "comma-separated IPv6 interface prefixes")
	flag.BoolVar(&autoRoute, "auto-route", false, "let sing-tun manage routes")
	flag.BoolVar(&strictRoute, "strict-route", false, "enable sing-tun strict route mode")
	flag.DurationVar(&udpTimeout, "udp-timeout", singtun.DefaultUDPTimeout, "UDP session timeout")
	flag.Parse()

	if proxyURL == "" {
		fmt.Fprintf(os.Stderr, "missing --proxy\n")
		flag.Usage()
		os.Exit(2)
	}
	parsedProxy, err := url.Parse(proxyURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid proxy URL: %v\n", err)
		os.Exit(2)
	}
	dial, err := proxyclient.NewClient(parsedProxy)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create proxy client: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	svc, err := singtun.Start(ctx, dial, singtun.Options{
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
		fmt.Fprintf(os.Stderr, "start singtun: %v\n", err)
		os.Exit(1)
	}
	defer svc.Close()

	tunName, _ := svc.Name()
	fmt.Printf("singtun started on %s via %s\n", tunName, parsedProxy.Redacted())
	<-ctx.Done()
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
