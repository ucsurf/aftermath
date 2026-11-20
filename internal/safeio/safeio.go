// Package safeio reads regular files inside caller-supplied roots.
// Symlinks that resolve outside those roots are not opened.
package safeio

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	// MaxRead is the default cap for heuristic content.
	MaxRead int64 = 1 << 20
	// MaxStream is the cap for an IOC byte scan or hash.
	MaxStream int64 = 32 << 20
)

var (
	// ErrEscape means a symlink resolved outside the allowed roots.
	ErrEscape = errors.New("symlink target is outside the scan roots")
	// ErrNotRegular means the path is not a regular file.
	ErrNotRegular = errors.New("not a regular file")
	// ErrOutside means the path is not inside the allowed roots.
	ErrOutside = errors.New("path is outside the scan roots")
)

// Roots is a set of directories a read is allowed to stay inside.
type Roots struct {
	list []string
}

// NewRoots cleans and keeps directories that are non-empty.
func NewRoots(paths ...string) Roots {
	var list []string
	for _, p := range paths {
		if strings.TrimSpace(p) == "" {
			continue
		}
		list = append(list, filepath.Clean(p))
	}
	return Roots{list: list}
}

// With returns roots that also include paths.
func (r Roots) With(paths ...string) Roots {
	all := append(append([]string{}, r.list...), paths...)
	return NewRoots(all...)
}
func (r Roots) Contains(path string) bool {
	path = filepath.Clean(path)
	for _, root := range r.list {
		if path == root {
			return true
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			continue
		}
		if rel == "." {
			return true
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		return true
	}
	return false
}

// File is a bounded read of a regular file.
type File struct {
	Path      string
	Data      []byte
	Truncated bool
}

// Read opens path if it stays inside roots and is a regular file.
// At most max bytes are returned. max <= 0 uses MaxRead.
func Read(path string, roots Roots, max int64) (File, error) {
	if max <= 0 {
		max = MaxRead
	}
	resolved, err := resolve(path, roots)
	if err != nil {
		return File{}, err
	}
	fi, err := os.Lstat(resolved)
	if err != nil {
		return File{}, err
	}
	if !fi.Mode().IsRegular() {
		return File{}, ErrNotRegular
	}
	f, err := os.Open(resolved)
	if err != nil {
		return File{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return File{}, err
	}
	if !st.Mode().IsRegular() {
		return File{}, ErrNotRegular
	}
	buf := make([]byte, max+1)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return File{}, err
	}
	truncated := int64(n) > max
	if truncated {
		n = int(max)
	}
	return File{Path: path, Data: append([]byte(nil), buf[:n]...), Truncated: truncated}, nil
}

// ContainsAny reports the first needle found in path, or "" if none match.
// Needles are returned as given; file bytes are not returned.
func ContainsAny(path string, roots Roots, needles []string, max int64) (string, error) {
	if len(needles) == 0 {
		return "", nil
	}
	if max <= 0 {
		max = MaxStream
	}
	resolved, err := resolve(path, roots)
	if err != nil {
		return "", err
	}
	fi, err := os.Lstat(resolved)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", ErrNotRegular
	}
	f, err := os.Open(resolved)
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", ErrNotRegular
	}
	overlap := 0
	for _, n := range needles {
		if len(n) > overlap {
			overlap = len(n)
		}
	}
	if overlap > 4096 {
		overlap = 4096
	}
	buf := make([]byte, 64*1024)
	var tail []byte
	var read int64
	for read < max {
		n, rerr := f.Read(buf)
		if n > 0 {
			chunk := append(append([]byte{}, tail...), buf[:n]...)
			for _, needle := range needles {
				if needle != "" && bytes.Contains(chunk, []byte(needle)) {
					return needle, nil
				}
			}
			if overlap > 0 && len(chunk) > overlap-1 {
				tail = append([]byte{}, chunk[len(chunk)-(overlap-1):]...)
			} else {
				tail = append([]byte{}, chunk...)
			}
			read += int64(n)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return "", rerr
		}
	}
	return "", nil
}

// HashSHA256 hashes a regular file inside roots.
// tooBig is true when the file is larger than max, in which case sum is nil.
func HashSHA256(path string, roots Roots, max int64) (sum []byte, tooBig bool, err error) {
	if max <= 0 {
		max = MaxStream
	}
	resolved, err := resolve(path, roots)
	if err != nil {
		return nil, false, err
	}
	fi, err := os.Lstat(resolved)
	if err != nil {
		return nil, false, err
	}
	if !fi.Mode().IsRegular() {
		return nil, false, ErrNotRegular
	}
	if fi.Size() > max {
		return nil, true, nil
	}
	f, err := os.Open(resolved)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	if !st.Mode().IsRegular() {
		return nil, false, ErrNotRegular
	}
	if st.Size() > max {
		return nil, true, nil
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, max+1)); err != nil {
		return nil, false, err
	}
	return h.Sum(nil), false, nil
}

// LstatInside stats path without following a symlink that leaves roots.
// The returned FileInfo is from Lstat (symlink itself when path is a symlink).
func LstatInside(path string, roots Roots) (os.FileInfo, string, error) {
	path = filepath.Clean(path)
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, "", err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		target, err := filepath.EvalSymlinks(path)
		if err != nil {
			return fi, "", err
		}
		if !roots.Contains(target) {
			return fi, target, ErrEscape
		}
		return fi, target, nil
	}
	if !roots.Contains(path) {
		return fi, "", ErrOutside
	}
	return fi, path, nil
}

func resolve(path string, roots Roots) (string, error) {
	path = filepath.Clean(path)
	fi, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		target, err := filepath.EvalSymlinks(path)
		if err != nil {
			return "", err
		}
		if !roots.Contains(target) {
			return "", ErrEscape
		}
		return target, nil
	}
	if !roots.Contains(path) {
		return "", ErrOutside
	}
	return path, nil
}

// SkipHeavyDir reports directory names that are caches or dependency trees.
func SkipHeavyDir(name string) bool {
	switch name {
	case "node_modules", ".git", "cache", "Cache", "CachedData", "CachedExtensions",
		"Code Cache", "GPUCache", "logs", "globalStorage", "workspaceStorage",
		"blob_storage", "Crashpad", "vendor", "dist", "coverage",
		"DawnGraphiteCache", "DawnWebGPUCache", "Local Storage", "Session Storage",
		"Shared Dictionary", "WebStorage", "CachedExtensionVSIXs":
		return true
	}
	if strings.HasSuffix(name, ".wants") || strings.HasSuffix(name, ".requires") {
		return true
	}
	return false
}

// SensitiveName reports credential-like file names that must not be opened.
func SensitiveName(name string) bool {
	n := strings.ToLower(name)
	switch n {
	case "auth.json", "credentials", "credentials.json", "cookies", "cookies.sqlite",
		".smtk", "smtk", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519":
		return true
	}
	if strings.HasPrefix(n, "id_rsa") || strings.HasPrefix(n, "id_ed25519") || strings.HasPrefix(n, "id_ecdsa") || strings.HasPrefix(n, "id_dsa") {
		return true
	}
	switch {
	case strings.HasSuffix(n, ".pem"), strings.HasSuffix(n, ".p12"), strings.HasSuffix(n, ".key"),
		strings.HasSuffix(n, ".keychain"), strings.HasSuffix(n, ".keychain-db"):
		return true
	}
	return false
}
