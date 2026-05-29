package singtun

import (
	"context"
	"net"
	"time"

	"github.com/chainreactors/proxyclient"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	singbufio "github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type handler struct {
	dial proxyclient.Dial
}

func newHandler(dial proxyclient.Dial) *handler {
	return &handler{dial: dial}
}

func (h *handler) PrepareConnection(
	network string,
	source M.Socksaddr,
	destination M.Socksaddr,
	routeContext tun.DirectRouteContext,
	timeout time.Duration,
) (tun.DirectRouteDestination, error) {
	switch network {
	case N.NetworkTCP, N.NetworkUDP:
		return nil, nil
	default:
		return nil, tun.ErrDrop
	}
}

func (h *handler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	outConn, err := h.dial(ctx, N.NetworkTCP, destination.String())
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	if err = N.ReportConnHandshakeSuccess(conn, outConn); err != nil {
		common.Close(conn, outConn)
		if onClose != nil {
			onClose(err)
		}
		return
	}
	err = singbufio.CopyConn(ctx, conn, outConn)
	if onClose != nil {
		onClose(err)
	}
}

func (h *handler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	outConn, err := h.dial(ctx, N.NetworkUDP, destination.String())
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	outPacketConn := singbufio.NewUnbindPacketConnWithAddr(outConn, destination)
	if err = N.ReportPacketConnHandshakeSuccess(conn, outPacketConn); err != nil {
		common.Close(conn, outPacketConn)
		if onClose != nil {
			onClose(err)
		}
		return
	}
	err = singbufio.CopyPacketConn(ctx, conn, outPacketConn)
	if onClose != nil {
		onClose(err)
	}
}
