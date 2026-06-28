module github.com/chainreactors/proxyclient/extra/vmess

go 1.24.0

toolchain go1.24.3

require (
	github.com/chainreactors/proxyclient v1.1.0
	github.com/sagernet/sing v0.8.11
	github.com/sagernet/sing-vmess v0.2.7
)

require (
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/cloudflare/circl v1.3.8 // indirect
	github.com/gofrs/uuid/v5 v5.3.2 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/metacubex/utls v1.7.3 // indirect
	golang.org/x/crypto v0.47.0 // indirect
	golang.org/x/exp v0.0.0-20240904232852-e7e105dedf7e // indirect
	golang.org/x/sys v0.41.0 // indirect
)

replace github.com/chainreactors/proxyclient => ../../
