module github.com/chainreactors/proxyclient/extra/anytls

go 1.24.0

toolchain go1.24.3

require (
	github.com/anytls/sing-anytls v0.0.13
	github.com/chainreactors/proxyclient v1.1.0
	github.com/sagernet/sing v0.7.6
)

require golang.org/x/sys v0.41.0 // indirect

replace github.com/chainreactors/proxyclient => ../../
