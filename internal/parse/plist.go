package parse

import (
	"bytes"
	"encoding/xml"
	"io"
	"strings"
)

// PlistInfo is the launchd fields aftermath reads.
type PlistInfo struct {
	Label   string
	Program []string
	Binary  bool
}

// ParseLaunchPlist extracts Label and Program/ProgramArguments.
// Binary plists are detected and not decoded.
func ParseLaunchPlist(data []byte) (PlistInfo, error) {
	if bytes.HasPrefix(data, []byte("bplist")) {
		return PlistInfo{Binary: true}, nil
	}
	data = AsUTF8(data)
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		return input, nil
	}
	var info PlistInfo
	var key string
	inKey := false
	want := false
	inArgs := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return info, nil
		}
		if err != nil {
			return info, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "key":
				inKey = true
			case "array":
				if want && key == "ProgramArguments" {
					inArgs = true
					want = false
				}
			case "true", "false":
				want = false
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "key":
				inKey = false
				want = true
			case "array":
				inArgs = false
			case "string":
				if !inArgs {
					want = false
				}
			}
		case xml.CharData:
			text := strings.TrimSpace(string(t))
			if text == "" {
				continue
			}
			if inKey {
				key = text
				continue
			}
			if inArgs {
				info.Program = append(info.Program, text)
				continue
			}
			if want && key == "Label" {
				info.Label = text
			}
			if want && key == "Program" {
				info.Program = append(info.Program, text)
			}
		}
	}
}
