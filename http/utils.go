package httpproxy

import (
	"encoding/base64"
)

var (
	authorization = "Proxy-Authorization"
)

func encodeBasicAuth(username, password string) string {
	const prefix = "Basic "
	return prefix + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
}
