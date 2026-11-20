package parse

import (
	"bytes"
	"encoding/binary"
	"unicode/utf16"
)

// AsUTF8 converts UTF-16 BOM text to UTF-8. Other input is returned as-is.
func AsUTF8(b []byte) []byte {
	if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE {
		return utf16ToUTF8(b[2:], binary.LittleEndian)
	}
	if len(b) >= 2 && b[0] == 0xFE && b[1] == 0xFF {
		return utf16ToUTF8(b[2:], binary.BigEndian)
	}
	if looksUTF16LE(b) {
		return utf16ToUTF8(b, binary.LittleEndian)
	}
	return b
}

func looksUTF16LE(b []byte) bool {
	if len(b) < 8 || len(b)%2 != 0 {
		return false
	}
	if b[0] == '<' || b[0] == '{' || bytes.HasPrefix(b, []byte("bplist")) {
		return false
	}
	zeros := 0
	n := 32
	if n > len(b) {
		n = len(b)
	}
	for i := 1; i < n; i += 2 {
		if b[i] == 0 {
			zeros++
		}
	}
	return zeros >= 3 && b[1] == 0
}

func utf16ToUTF8(b []byte, order binary.ByteOrder) []byte {
	if len(b)%2 == 1 {
		b = b[:len(b)-1]
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = order.Uint16(b[i*2:])
	}
	return []byte(string(utf16.Decode(u)))
}
