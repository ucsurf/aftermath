// Package ioc loads versioned indicator packs and matches them locally.
package ioc

import (
	"bytes"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed packs/*.yaml
var packFS embed.FS

// Pack is one indicator document.
type Pack struct {
	Version    int         `yaml:"version"`
	ID         string      `yaml:"id"`
	Name       string      `yaml:"name"`
	Updated    string      `yaml:"updated"`
	Indicators []Indicator `yaml:"indicators"`
}

// Indicator is one published indicator.
type Indicator struct {
	ID          string `yaml:"id"`
	Severity    string `yaml:"severity"`
	Title       string `yaml:"title"`
	Description string `yaml:"description"`
	Source      string `yaml:"source"`
	Match       Match  `yaml:"match"`
}

// Match describes where an indicator is applied.
// Paths are relative. ".." and absolute paths are rejected.
type Match struct {
	Bases         []string `yaml:"bases"`
	Paths         []string `yaml:"paths"`
	ListRoots     []string `yaml:"list_roots"`
	PathContains  []string `yaml:"path_contains"`
	Basenames     []string `yaml:"basenames"`
	ContentAny    []string `yaml:"content_any"`
	SHA256        []string `yaml:"sha256"`
	Scope         string   `yaml:"scope"`
	NamePrefix    string   `yaml:"name_prefix"`
	NameHexLength int      `yaml:"name_hex_length"`
}

// LoadEmbedded reads the packs compiled into the binary.
func LoadEmbedded() ([]Pack, error) {
	entries, err := fs.ReadDir(packFS, "packs")
	if err != nil {
		return nil, err
	}
	var out []Pack
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		b, err := packFS.ReadFile("packs/" + e.Name())
		if err != nil {
			return nil, err
		}
		p, err := Parse(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, errors.New("no embedded ioc packs")
	}
	return out, nil
}

// Parse decodes and validates a pack. Alias-heavy YAML is rejected.
func Parse(data []byte) (Pack, error) {
	if len(data) > 1<<20 {
		return Pack{}, errors.New("ioc pack exceeds 1MiB")
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var node yaml.Node
	if err := dec.Decode(&node); err != nil {
		return Pack{}, err
	}
	if aliases := countAliases(node); aliases > 50 {
		return Pack{}, errors.New("ioc pack has too many yaml aliases")
	}
	var p Pack
	if err := node.Decode(&p); err != nil {
		return Pack{}, err
	}
	if err := p.Validate(); err != nil {
		return Pack{}, err
	}
	return p, nil
}

func countAliases(n yaml.Node) int {
	c := 0
	if n.Kind == yaml.AliasNode {
		c++
	}
	for i := range n.Content {
		c += countAliases(*n.Content[i])
	}
	return c
}

// Validate checks the pack structure. It does not fetch source URLs.
func (p Pack) Validate() error {
	if p.Version != 1 {
		return errors.New("ioc pack version must be 1")
	}
	if strings.TrimSpace(p.ID) == "" {
		return errors.New("ioc pack id is required")
	}
	if len(p.Indicators) == 0 || len(p.Indicators) > 500 {
		return errors.New("ioc pack must contain 1 to 500 indicators")
	}
	seen := map[string]bool{}
	for _, ind := range p.Indicators {
		if err := ind.Validate(); err != nil {
			return fmt.Errorf("%s: %w", ind.ID, err)
		}
		if seen[ind.ID] {
			return fmt.Errorf("duplicate indicator id %s", ind.ID)
		}
		seen[ind.ID] = true
	}
	return nil
}

// Validate checks one indicator.
func (ind Indicator) Validate() error {
	if strings.TrimSpace(ind.ID) == "" {
		return errors.New("id is required")
	}
	switch strings.ToLower(ind.Severity) {
	case "info", "low", "medium", "high", "critical":
	default:
		return errors.New("severity must be info, low, medium, high, or critical")
	}
	if strings.TrimSpace(ind.Title) == "" {
		return errors.New("title is required")
	}
	u, err := url.Parse(ind.Source)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("source must be an https URL")
	}
	m := ind.Match
	if m.Scope == "temp" {
		if m.NamePrefix == "" || strings.ContainsAny(m.NamePrefix, `/\`) || len(m.NamePrefix) > 32 {
			return errors.New("temp scope needs a simple name_prefix")
		}
		if m.NameHexLength < 1 || m.NameHexLength > 64 {
			return errors.New("name_hex_length out of range")
		}
		return nil
	}
	if m.Scope != "" && m.Scope != "temp" {
		return errors.New("unknown match scope")
	}
	if len(m.Paths) == 0 && len(m.ListRoots) == 0 {
		return errors.New("match needs paths or list_roots")
	}
	for _, p := range append(append([]string{}, m.Paths...), m.ListRoots...) {
		if !validRel(p) {
			return fmt.Errorf("path %q must be relative and must not contain ..", p)
		}
	}
	for _, base := range m.Bases {
		switch base {
		case "home", "project", "system":
		default:
			return fmt.Errorf("unknown base %q", base)
		}
	}
	if len(m.ContentAny) > 20 {
		return errors.New("too many content needles")
	}
	for _, c := range m.ContentAny {
		if c == "" || len(c) > 512 {
			return errors.New("content needle length must be 1 to 512")
		}
	}
	for _, s := range m.SHA256 {
		if len(s) != 64 {
			return errors.New("sha256 must be 64 hex characters")
		}
		if _, err := hex.DecodeString(s); err != nil {
			return errors.New("sha256 is not hex")
		}
	}
	for _, c := range m.PathContains {
		if strings.TrimSpace(c) == "" || len(c) > 200 {
			return errors.New("path_contains length must be 1 to 200")
		}
	}
	return nil
}

func validRel(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\`) {
		return false
	}
	if len(p) >= 2 && p[1] == ':' {
		return false
	}
	if strings.Contains(p, "..") {
		return false
	}
	return true
}
