package tun

import (
	"context"
	"errors"
	"sync"

	"github.com/chainreactors/proxyclient"
	sagtun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"
)

type Service interface {
	Start() error
	Close() error
	Name() (string, error)
	Running() bool
	Err() error
}

var ErrClosed = errors.New("tun: service is closed")

type lifecycleState uint8

const (
	stateNew lifecycleState = iota
	stateStarting
	stateRunning
	stateClosing
	stateClosed
)

type lifecycleResource interface {
	Start() error
	Close() error
}

type tunResource interface {
	lifecycleResource
	Name() (string, error)
}

type runtimeState struct {
	networkMonitor   lifecycleResource
	interfaceMonitor lifecycleResource
	tunDevice        tunResource
	stack            lifecycleResource
}

type runtimeFactory func(ctx context.Context, dial proxyclient.Dial, options Options) (*runtimeState, error)

type service struct {
	ctx     context.Context
	cancel  context.CancelFunc
	dial    proxyclient.Dial
	options Options
	name    string

	newRuntime runtimeFactory

	mu       sync.Mutex
	state    lifecycleState
	runtime  *runtimeState
	lastErr  error
	closeErr error
}

func New(ctx context.Context, dial proxyclient.Dial, options Options) (Service, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if dial == nil {
		return nil, proxyclient.ErrNilDial
	}

	options = options.withDefaults()
	if err := options.validate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	return &service{
		ctx:        ctx,
		cancel:     cancel,
		dial:       dial,
		options:    options,
		name:       options.Name,
		newRuntime: createRuntime,
		state:      stateNew,
	}, nil
}

func createRuntime(ctx context.Context, dial proxyclient.Dial, options Options) (*runtimeState, error) {
	interfaceFinder := control.NewDefaultInterfaceFinder()
	networkMonitor, err := sagtun.NewNetworkUpdateMonitor(options.Logger)
	if err != nil {
		return nil, err
	}
	runtime := &runtimeState{
		networkMonitor: networkMonitor,
	}
	interfaceMonitor, err := sagtun.NewDefaultInterfaceMonitor(networkMonitor, options.Logger, sagtun.DefaultInterfaceMonitorOptions{
		InterfaceFinder: interfaceFinder,
	})
	if err != nil {
		runtime.close()
		return nil, err
	}
	runtime.interfaceMonitor = interfaceMonitor

	tunOptions := options.tunOptions(interfaceFinder, interfaceMonitor)
	tunDevice, err := sagtun.New(tunOptions)
	if err != nil {
		runtime.close()
		return nil, err
	}
	runtime.tunDevice = tunDevice

	stack, err := sagtun.NewStack(options.Stack, sagtun.StackOptions{
		Context:         ctx,
		Tun:             tunDevice,
		TunOptions:      tunOptions,
		UDPTimeout:      options.UDPTimeout,
		Handler:         newHandler(dial),
		Logger:          options.Logger,
		InterfaceFinder: interfaceFinder,
	})
	if err != nil {
		runtime.close()
		return nil, err
	}
	runtime.stack = stack
	return runtime, nil
}

func Start(ctx context.Context, dial proxyclient.Dial, options Options) (Service, error) {
	svc, err := New(ctx, dial, options)
	if err != nil {
		return nil, err
	}
	if err = svc.Start(); err != nil {
		svc.Close()
		return nil, err
	}
	return svc, nil
}

func (s *service) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch s.state {
	case stateRunning:
		return nil
	case stateClosing, stateClosed:
		s.lastErr = ErrClosed
		return ErrClosed
	}
	if err := s.ctx.Err(); err != nil {
		s.lastErr = err
		return err
	}

	s.state = stateStarting
	runtime, err := s.newRuntime(s.ctx, s.dial, s.options)
	if err != nil {
		s.state = stateNew
		s.lastErr = err
		return err
	}
	if err = runtime.start(); err != nil {
		if closeErr := runtime.close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
		s.state = stateNew
		s.lastErr = err
		return err
	}

	s.runtime = runtime
	if runtime.tunDevice != nil {
		if name, nameErr := runtime.tunDevice.Name(); nameErr == nil && name != "" {
			s.name = name
		}
	}
	s.state = stateRunning
	s.lastErr = nil
	return nil
}

func (s *service) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state == stateClosed {
		return s.closeErr
	}

	runtime := s.runtime
	s.runtime = nil
	s.state = stateClosing
	s.cancel()
	s.closeErr = runtime.close()
	if s.closeErr != nil {
		s.lastErr = s.closeErr
	}
	s.state = stateClosed
	return s.closeErr
}

func (s *service) Name() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.runtime != nil && s.runtime.tunDevice != nil {
		name, err := s.runtime.tunDevice.Name()
		if err != nil {
			return "", err
		}
		if name != "" {
			s.name = name
			return name, nil
		}
	}
	return s.name, nil
}

func (s *service) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state == stateRunning
}

func (s *service) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastErr
}

func (r *runtimeState) start() error {
	for _, resource := range []lifecycleResource{
		r.networkMonitor,
		r.interfaceMonitor,
		r.stack,
		r.tunDevice,
	} {
		if resource == nil {
			continue
		}
		if err := resource.Start(); err != nil {
			return err
		}
	}
	return nil
}

func (r *runtimeState) close() error {
	if r == nil {
		return nil
	}
	return common.Close(r.stack, r.tunDevice, r.interfaceMonitor, r.networkMonitor)
}
