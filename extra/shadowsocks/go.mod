module github.com/chainreactors/proxyclient/extra/shadowsocks

go 1.25.0

require (
	github.com/chainreactors/proxyclient v1.1.0
	github.com/shadowsocks/go-shadowsocks2 v0.1.5
)

require (
	github.com/riobard/go-bloom v0.0.0-20200614022211-cdc8013cb5b3 // indirect
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
)

replace github.com/chainreactors/proxyclient => ../../
