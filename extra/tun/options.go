package tun

import (
	"fmt"
	"net/netip"
	"time"

	sagtun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
)

const (
	StackGVisor = "gvisor"
	StackMixed  = "mixed"
	StackSystem = "system"

	DefaultStack        = StackGVisor
	DefaultMTU   uint32 = 9000
)

var (
	DefaultInet4Prefix = netip.MustParsePrefix("172.19.0.1/30")
	DefaultUDPTimeout  = 5 * time.Minute
)

type Options struct {
	Name        string
	MTU         uint32
	Stack       string
	Inet4       []netip.Prefix
	Inet6       []netip.Prefix
	UDPTimeout  time.Duration
	AutoRoute   bool
	StrictRoute bool
	Logger      logger.Logger
}

func (o Options) withDefaults() Options {
	if o.Name == "" {
		o.Name = sagtun.CalculateInterfaceName("")
	}
	if o.MTU == 0 {
		o.MTU = DefaultMTU
	}
	if o.Stack == "" {
		o.Stack = DefaultStack
	}
	if len(o.Inet4) == 0 && len(o.Inet6) == 0 {
		o.Inet4 = []netip.Prefix{DefaultInet4Prefix}
	}
	if o.UDPTimeout == 0 {
		o.UDPTimeout = DefaultUDPTimeout
	}
	if o.Logger == nil {
		o.Logger = logger.NOP()
	}
	return o
}

func (o Options) validate() error {
	switch o.Stack {
	case StackGVisor, StackMixed, StackSystem:
		return nil
	default:
		return fmt.Errorf("tun: unknown stack %q", o.Stack)
	}
}

func (o Options) tunOptions(interfaceFinder control.InterfaceFinder, interfaceMonitor sagtun.DefaultInterfaceMonitor) sagtun.Options {
	return sagtun.Options{
		Name:             o.Name,
		Inet4Address:     o.Inet4,
		Inet6Address:     o.Inet6,
		MTU:              o.MTU,
		AutoRoute:        o.AutoRoute,
		StrictRoute:      o.StrictRoute,
		InterfaceFinder:  interfaceFinder,
		InterfaceMonitor: interfaceMonitor,
		Logger:           o.Logger,
	}
}
