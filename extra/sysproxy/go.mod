module github.com/chainreactors/proxyclient/extra/sysproxy

go 1.24.0

toolchain go1.24.3

require (
	github.com/chainreactors/proxyclient v0.0.0-00010101000000-000000000000
	golang.org/x/sys v0.33.0
)

replace github.com/chainreactors/proxyclient => ../../
