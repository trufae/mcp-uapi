package mcpserver

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type Uint8 uint8
type Uint16 uint16
type Uint32 uint32
type Uint64 uint64
type ConstUint64 uint64
type ConstUint32 uint32

const linuxFIONREAD = 0x541b

func (u *Uint8) UnmarshalJSON(data []byte) error {
	value, err := parseUnsigned(data, 8)
	if err != nil {
		return err
	}
	*u = Uint8(value)
	return nil
}

func (u *Uint16) UnmarshalJSON(data []byte) error {
	value, err := parseUnsigned(data, 16)
	if err != nil {
		return err
	}
	*u = Uint16(value)
	return nil
}

func (u *Uint32) UnmarshalJSON(data []byte) error {
	value, err := parseUnsigned(data, 32)
	if err != nil {
		return err
	}
	*u = Uint32(value)
	return nil
}

func (u *Uint64) UnmarshalJSON(data []byte) error {
	value, err := parseUnsigned(data, 64)
	if err != nil {
		return err
	}
	*u = Uint64(value)
	return nil
}

func (u *ConstUint64) UnmarshalJSON(data []byte) error {
	value, err := parseConstOrUnsigned(data, 64)
	if err != nil {
		return err
	}
	*u = ConstUint64(value)
	return nil
}

func (u *ConstUint32) UnmarshalJSON(data []byte) error {
	value, err := parseConstOrUnsigned(data, 32)
	if err != nil {
		return err
	}
	*u = ConstUint32(value)
	return nil
}

func parseUnsigned(data []byte, bits int) (uint64, error) {
	s := strings.TrimSpace(string(data))
	if s == "" || s == "null" {
		return 0, nil
	}
	if strings.HasPrefix(s, "\"") {
		var text string
		if err := json.Unmarshal(data, &text); err != nil {
			return 0, err
		}
		text = strings.TrimSpace(text)
		if text == "" {
			return 0, nil
		}
		value, err := strconv.ParseUint(text, 0, bits)
		if err != nil {
			return 0, fmt.Errorf("parse unsigned integer %q: %w", text, err)
		}
		return value, nil
	}
	value, err := strconv.ParseUint(s, 10, bits)
	if err != nil {
		return 0, fmt.Errorf("parse unsigned integer %q: %w", s, err)
	}
	return value, nil
}

func parseConstOrUnsigned(data []byte, bits int) (uint64, error) {
	s := strings.TrimSpace(string(data))
	if s == "" || s == "null" {
		return 0, nil
	}
	if strings.HasPrefix(s, "\"") {
		var text string
		if err := json.Unmarshal(data, &text); err != nil {
			return 0, err
		}
		return parseConstExpression(text, bits)
	}
	return parseUnsigned(data, bits)
}

func parseConstExpression(text string, bits int) (uint64, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return 0, nil
	}
	if value, err := strconv.ParseUint(text, 0, bits); err == nil {
		return value, nil
	}
	var value uint64
	parts := strings.FieldsFunc(text, func(r rune) bool { return r == '|' || r == ',' || r == ' ' || r == '\t' || r == '\n' })
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		constant, ok := lookupConstant(part)
		if !ok {
			return 0, fmt.Errorf("unknown constant %q", part)
		}
		value |= constant
	}
	if bits < 64 && value >= 1<<bits {
		return 0, fmt.Errorf("constant expression %q overflows uint%d", text, bits)
	}
	return value, nil
}

func lookupConstant(name string) (uint64, bool) {
	key := normalizeConstantName(name)
	value, ok := namedConstants()[key]
	return value, ok
}

func normalizeConstantName(name string) string {
	name = strings.TrimSpace(strings.ToUpper(name))
	name = strings.TrimPrefix(name, "UNIX.")
	name = strings.ReplaceAll(name, "-", "_")
	return name
}

func hex8(v uint8) string     { return fmt.Sprintf("0x%02x", v) }
func hex16(v uint16) string   { return fmt.Sprintf("0x%04x", v) }
func hex32(v uint32) string   { return fmt.Sprintf("0x%08x", v) }
func hex64(v uint64) string   { return fmt.Sprintf("0x%016x", v) }
func hexPtr(v uintptr) string { return fmt.Sprintf("0x%016x", uint64(v)) }

func signedConst(value int) uint64 { return uint64(int64(value)) }

func checksum64(data []byte) string {
	var sum uint64 = 1469598103934665603
	for _, b := range data {
		sum ^= uint64(b)
		sum *= 1099511628211
	}
	return hex64(sum)
}

func namedConstants() map[string]uint64 {
	return platformNamedConstants()
}
