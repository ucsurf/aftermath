//go:build windows

package autorun

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// Registry access is KEY_QUERY_VALUE only. This file does not import
// golang.org/x/sys/windows/registry because that package imports net.

const (
	hkeyCurrentUser   = 0x80000001
	hkeyLocalMachine  = 0x80000002
	keyQueryValue     = 0x0001
	errorSuccess      = 0
	errorFileNotFound = 2
	errorMoreData     = 234
	errorNoMoreItems  = 259
	regSZ             = 1
	regExpandSZ       = 2
)

var (
	modadvapi32       = syscall.NewLazyDLL("advapi32.dll")
	procRegOpenKeyExW = modadvapi32.NewProc("RegOpenKeyExW")
	procRegCloseKey   = modadvapi32.NewProc("RegCloseKey")
	procRegEnumValueW = modadvapi32.NewProc("RegEnumValueW")
)

type windowsRegistry struct{}

func platformRegistry() (RegistryView, error) {
	return windowsRegistry{}, nil
}

func (windowsRegistry) ReadKey(logical string) (map[string]string, error) {
	hive, path, err := splitHive(logical)
	if err != nil {
		return nil, err
	}
	sub, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	var h syscall.Handle
	r, _, callErr := procRegOpenKeyExW.Call(
		hive,
		uintptr(unsafe.Pointer(sub)),
		0,
		keyQueryValue,
		uintptr(unsafe.Pointer(&h)),
	)
	if r == errorFileNotFound {
		return nil, os.ErrNotExist
	}
	if r != errorSuccess {
		if callErr != nil && callErr != syscall.Errno(0) {
			return nil, fmt.Errorf("open registry key: %w", callErr)
		}
		return nil, errors.New("open registry key failed")
	}
	defer procRegCloseKey.Call(uintptr(h))

	out := map[string]string{}
	nameBuf := make([]uint16, 16383)
	dataBuf := make([]byte, 32*1024)
	for i := 0; i < 4096; i++ {
		nameLen := uint32(len(nameBuf))
		dataLen := uint32(len(dataBuf))
		var typ uint32
		r, _, _ := procRegEnumValueW.Call(
			uintptr(h),
			uintptr(i),
			uintptr(unsafe.Pointer(&nameBuf[0])),
			uintptr(unsafe.Pointer(&nameLen)),
			0,
			uintptr(unsafe.Pointer(&typ)),
			uintptr(unsafe.Pointer(&dataBuf[0])),
			uintptr(unsafe.Pointer(&dataLen)),
		)
		if r == errorNoMoreItems {
			break
		}
		if r == errorMoreData {
			continue
		}
		if r != errorSuccess {
			return out, errors.New("enumerate registry values failed")
		}
		if nameLen > uint32(len(nameBuf)) {
			nameLen = uint32(len(nameBuf))
		}
		name := syscall.UTF16ToString(nameBuf[:nameLen])
		if typ != regSZ && typ != regExpandSZ {
			out[name] = ""
			continue
		}
		if dataLen > uint32(len(dataBuf)) {
			dataLen = uint32(len(dataBuf))
		}
		n := int(dataLen / 2)
		u := make([]uint16, n)
		for j := 0; j < n; j++ {
			u[j] = uint16(dataBuf[j*2]) | uint16(dataBuf[j*2+1])<<8
		}
		out[name] = syscall.UTF16ToString(u)
	}
	return out, nil
}

func splitHive(logical string) (uintptr, string, error) {
	const hkcu = `HKCU\`
	const hklm = `HKLM\`
	switch {
	case len(logical) > len(hkcu) && logical[:len(hkcu)] == hkcu:
		return hkeyCurrentUser, logical[len(hkcu):], nil
	case len(logical) > len(hklm) && logical[:len(hklm)] == hklm:
		return hkeyLocalMachine, logical[len(hklm):], nil
	default:
		return 0, "", errors.New("unsupported registry hive")
	}
}
