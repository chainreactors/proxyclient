module github.com/chainreactors/proxyclient/extra/clash

go 1.24.0

toolchain go1.24.3

require (
	github.com/chainreactors/proxyclient v1.0.4-0.20260218115902-74a84a4535b0
	github.com/chainreactors/proxyclient/extra/trojan v0.0.0
	gopkg.in/yaml.v3 v3.0.1
)

replace (
	github.com/chainreactors/proxyclient => ../../
	github.com/chainreactors/proxyclient/extra/trojan => ../trojan
)
