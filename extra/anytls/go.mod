module github.com/chainreactors/proxyclient/extra/anytls

go 1.25.0

require (
	github.com/anytls/sing-anytls v0.0.11
	github.com/chainreactors/proxyclient v1.1.0
	github.com/sagernet/sing v0.7.6
)

require golang.org/x/sys v0.45.0 // indirect

replace github.com/chainreactors/proxyclient => ../../
