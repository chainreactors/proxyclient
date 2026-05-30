//go:build !windows && !darwin && !linux

package sysproxy

import (
	"fmt"
	"runtime"
)

const platformName = "other"

func platformDetect() (*DetectedProxy, error) {
	return nil, fmt.Errorf("sysproxy: unsupported platform %s/%s", runtime.GOOS, runtime.GOARCH)
}

func platformSet(cfg Config) (any, error) {
	return nil, fmt.Errorf("sysproxy: unsupported platform %s/%s", runtime.GOOS, runtime.GOARCH)
}

func platformUnset() error {
	return fmt.Errorf("sysproxy: unsupported platform %s/%s", runtime.GOOS, runtime.GOARCH)
}

func platformRestore(saved any) error {
	return fmt.Errorf("sysproxy: unsupported platform %s/%s", runtime.GOOS, runtime.GOARCH)
}
