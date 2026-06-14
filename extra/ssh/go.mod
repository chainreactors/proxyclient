module github.com/chainreactors/proxyclient/extra/ssh

go 1.25.0

require (
	github.com/chainreactors/proxyclient v1.1.0
	golang.org/x/crypto v0.53.0
)

require golang.org/x/sys v0.46.0 // indirect

replace github.com/chainreactors/proxyclient => ../../
