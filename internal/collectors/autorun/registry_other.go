//go:build !windows

package autorun

func platformRegistry() (RegistryView, error) {
	return nil, nil
}
