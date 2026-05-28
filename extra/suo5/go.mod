module github.com/chainreactors/proxyclient/extra/suo5

go 1.24.0

toolchain go1.24.3

require (
	github.com/chainreactors/proxyclient v1.0.4-0.20260218115902-74a84a4535b0
	github.com/zema1/suo5 v1.3.2-0.20250219115440-31983ee59a83
)

require (
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/cloudflare/circl v1.3.8 // indirect
	github.com/go-gost/gosocks5 v0.3.0 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/kataras/golog v0.1.8 // indirect
	github.com/kataras/pio v0.0.11 // indirect
	github.com/klauspost/compress v1.17.8 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/refraction-networking/utls v1.6.4 // indirect
	github.com/zema1/rawhttp v0.2.0 // indirect
	golang.org/x/crypto v0.33.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
)

replace (
	github.com/chainreactors/proxyclient => ../../
	github.com/zema1/suo5 => github.com/M09Ic/suo5 v1.3.4
)
