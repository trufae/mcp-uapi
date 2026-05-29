package mcpserver

import (
	"encoding/json"
	"testing"
)

func TestUintParsersAcceptHexStrings(t *testing.T) {
	var value struct {
		A Uint8  `json:"a"`
		B Uint16 `json:"b"`
		C Uint32 `json:"c"`
		D Uint64 `json:"d"`
	}
	data := []byte(`{"a":"0xff","b":"0x1234","c":"0x89abcdef","d":"0xffffffffffffffff"}`)
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if value.A != 0xff || value.B != 0x1234 || value.C != 0x89abcdef || value.D != 0xffffffffffffffff {
		t.Fatalf("unexpected parsed values: %#v", value)
	}
}

func TestConstParserAcceptsExpressions(t *testing.T) {
	var value struct {
		Flags ConstUint64 `json:"flags"`
	}
	if err := json.Unmarshal([]byte(`{"flags":"O_RDWR|O_CREAT|O_CLOEXEC"}`), &value); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	want, err := parseConstExpression("O_RDWR|O_CREAT|O_CLOEXEC", 64)
	if err != nil {
		t.Fatalf("parseConstExpression: %v", err)
	}
	if uint64(value.Flags) != want {
		t.Fatalf("Flags = %d, want %d", value.Flags, want)
	}
}
