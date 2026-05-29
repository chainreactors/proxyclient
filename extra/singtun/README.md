# singtun

`extra/singtun` exposes a system TUN device and forwards TCP/UDP sessions through
an existing `proxyclient.Dial`.

This module depends on `github.com/sagernet/sing-tun` and follows its license
constraints. It is intentionally isolated from the core `proxyclient` module.

## Usage

```go
proxyURL, _ := url.Parse("socks5://127.0.0.1:1080")
dial, _ := proxyclient.NewClient(proxyURL)

svc, err := singtun.Start(ctx, dial, singtun.Options{})
if err != nil {
    panic(err)
}
defer svc.Close()
```

For explicit lifecycle management, use `New` and start it later:

```go
svc, _ := singtun.New(ctx, dial, singtun.Options{})
defer svc.Close()

if err := svc.Start(); err != nil {
    return err
}
if svc.Running() {
    name, _ := svc.Name()
    _ = name
}
```

`New` only validates and stores configuration. `Start` creates the TUN runtime,
and failed starts clean up partially-created resources. `Close` is idempotent
and can be called before or after `Start`.

The default stack is `gvisor`, which requires building with the `with_gvisor`
tag:

```bash
go test -tags with_gvisor ./...
go build -tags with_gvisor ./example/singtun
```

Creating a TUN device usually requires administrator/root privileges. Route
management is disabled by default; configure OS routes yourself or set
`Options.AutoRoute` when you explicitly want sing-tun to manage routes.
