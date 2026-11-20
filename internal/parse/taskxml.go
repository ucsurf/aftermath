package parse

import (
	"bytes"
	"encoding/xml"
	"io"
	"strings"
)

// TaskInfo is the command portion of a Windows task XML file.
type TaskInfo struct {
	URI      string
	Commands []string
}

// ParseTaskXML reads Command, Arguments, and URI. Other fields are ignored.
func ParseTaskXML(data []byte) (TaskInfo, error) {
	data = AsUTF8(data)
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		return input, nil
	}
	var info TaskInfo
	var cur string
	var cmd, args string
	flush := func() {
		c := strings.TrimSpace(cmd)
		if c == "" {
			cmd, args = "", ""
			return
		}
		if strings.TrimSpace(args) != "" {
			c = c + " " + strings.TrimSpace(args)
		}
		info.Commands = append(info.Commands, c)
		cmd, args = "", ""
	}
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			flush()
			return info, nil
		}
		if err != nil {
			return info, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			cur = t.Name.Local
			if cur == "Exec" {
				flush()
			}
		case xml.EndElement:
			if t.Name.Local == "Exec" {
				flush()
			}
			cur = ""
		case xml.CharData:
			text := strings.TrimSpace(string(t))
			if text == "" {
				continue
			}
			switch cur {
			case "URI":
				if info.URI == "" {
					info.URI = text
				}
			case "Command":
				cmd = text
			case "Arguments":
				args = text
			}
		}
	}
}
