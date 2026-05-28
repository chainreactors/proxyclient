module github.com/chainreactors/proxyclient/extra/ssh

go 1.24.0

toolchain go1.24.3

require (
	github.com/chainreactors/proxyclient v1.0.4-0.20260218115902-74a84a4535b0
	golang.org/x/crypto v0.47.0
)

require golang.org/x/sys v0.41.0 // indirect

replace github.com/chainreactors/proxyclient => ../../
