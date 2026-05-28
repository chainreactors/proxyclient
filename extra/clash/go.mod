module github.com/chainreactors/proxyclient/extra/clash

go 1.24.0

toolchain go1.24.3

require (
	github.com/chainreactors/proxyclient v1.0.4-0.20260218115902-74a84a4535b0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/riobard/go-bloom v0.0.0-20200614022211-cdc8013cb5b3 // indirect
	github.com/shadowsocks/go-shadowsocks2 v0.1.5 // indirect
	golang.org/x/crypto v0.47.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
)

replace github.com/chainreactors/proxyclient => ../../
