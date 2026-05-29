package tun

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"

	"github.com/chainreactors/proxyclient"
)

func TestNewValidatesStack(t *testing.T) {
	_, err := New(context.Background(), noopDial, Options{Stack: "unknown"})
	if err == nil {
		t.Fatal("expected invalid stack error")
	}
}

func TestCloseBeforeStart(t *testing.T) {
	svc, err := New(context.Background(), noopDial, Options{})
	if err != nil {
		t.Fatal(err)
	}
	service := svc.(*service)
	called := false
	service.newRuntime = func(context.Context, proxyclient.Dial, Options) (*runtimeState, error) {
		called = true
		return newFakeRuntime(nil, nil), nil
	}

	if svc.Running() {
		t.Fatal("service should not be running before Start")
	}
	if name, err := svc.Name(); err != nil || name == "" {
		t.Fatalf("expected configured name before Start, got name=%q err=%v", name, err)
	}
	if err := svc.Close(); err != nil {
		t.Fatalf("Close before Start failed: %v", err)
	}
	if err := svc.Start(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Start after Close should return ErrClosed, got %v", err)
	}
	if called {
		t.Fatal("Start after Close should not create runtime resources")
	}
	if err := svc.Close(); err != nil {
		t.Fatalf("second Close failed: %v", err)
	}
	if !errors.Is(svc.Err(), ErrClosed) {
		t.Fatalf("expected ErrClosed from Err, got %v", svc.Err())
	}
}

func TestServiceStartCloseLifecycle(t *testing.T) {
	order := make([]string, 0, 8)
	runtime := newFakeRuntime(&order, nil)

	svc, err := New(context.Background(), noopDial, Options{})
	if err != nil {
		t.Fatal(err)
	}
	service := svc.(*service)
	service.newRuntime = func(context.Context, proxyclient.Dial, Options) (*runtimeState, error) {
		return runtime, nil
	}

	if err := svc.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	if !svc.Running() {
		t.Fatal("service should be running after Start")
	}
	if err := svc.Start(); err != nil {
		t.Fatalf("second Start should be a no-op: %v", err)
	}
	name, err := svc.Name()
	if err != nil {
		t.Fatal(err)
	}
	if name != "testtun0" {
		t.Fatalf("expected runtime tun name, got %q", name)
	}

	if err := svc.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if svc.Running() {
		t.Fatal("service should not be running after Close")
	}
	if err := svc.Close(); err != nil {
		t.Fatalf("second Close failed: %v", err)
	}

	want := []string{
		"network.start",
		"interface.start",
		"stack.start",
		"tun.start",
		"stack.close",
		"tun.close",
		"interface.close",
		"network.close",
	}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("unexpected lifecycle order:\nwant %v\n got %v", want, order)
	}
	if svc.Err() != nil {
		t.Fatalf("expected nil Err, got %v", svc.Err())
	}
}

func TestServiceStartFailureCleansRuntime(t *testing.T) {
	startErr := errors.New("stack start failed")
	order := make([]string, 0, 8)
	runtime := newFakeRuntime(&order, map[string]error{
		"stack": startErr,
	})

	svc, err := New(context.Background(), noopDial, Options{})
	if err != nil {
		t.Fatal(err)
	}
	service := svc.(*service)
	service.newRuntime = func(context.Context, proxyclient.Dial, Options) (*runtimeState, error) {
		return runtime, nil
	}

	err = svc.Start()
	if !errors.Is(err, startErr) {
		t.Fatalf("expected stack start error, got %v", err)
	}
	if svc.Running() {
		t.Fatal("service should not be running after failed Start")
	}
	if !errors.Is(svc.Err(), startErr) {
		t.Fatalf("expected Err to keep start error, got %v", svc.Err())
	}
	if err := svc.Close(); err != nil {
		t.Fatalf("Close after failed Start should be clean: %v", err)
	}

	want := []string{
		"network.start",
		"interface.start",
		"stack.start",
		"stack.close",
		"tun.close",
		"interface.close",
		"network.close",
	}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("unexpected lifecycle order:\nwant %v\n got %v", want, order)
	}
}

func noopDial(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("unexpected dial")
}

func newFakeRuntime(order *[]string, startErrs map[string]error) *runtimeState {
	return &runtimeState{
		networkMonitor:   newFakeResource("network", order, startErrs),
		interfaceMonitor: newFakeResource("interface", order, startErrs),
		stack:            newFakeResource("stack", order, startErrs),
		tunDevice: &fakeTunResource{
			fakeResource: newFakeResource("tun", order, startErrs),
			name:         "testtun0",
		},
	}
}

func newFakeResource(name string, order *[]string, startErrs map[string]error) fakeResource {
	return fakeResource{
		name:      name,
		order:     order,
		startErrs: startErrs,
	}
}

type fakeResource struct {
	name      string
	order     *[]string
	startErrs map[string]error
}

func (r fakeResource) Start() error {
	if r.order != nil {
		*r.order = append(*r.order, r.name+".start")
	}
	return r.startErrs[r.name]
}

func (r fakeResource) Close() error {
	if r.order != nil {
		*r.order = append(*r.order, r.name+".close")
	}
	return nil
}

type fakeTunResource struct {
	fakeResource
	name string
}

func (r *fakeTunResource) Name() (string, error) {
	return r.name, nil
}
