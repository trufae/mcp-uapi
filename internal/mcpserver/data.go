package mcpserver

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"unicode/utf8"
)

type fillSpec struct {
	Mode   string `json:"mode"`
	Length Uint64 `json:"length"`
	Value  Uint64 `json:"value"`
}

func encodeBytes(data []byte, encoding string) (map[string]any, error) {
	if encoding == "" {
		encoding = "base64"
	}
	result := map[string]any{"encoding": encoding, "length": len(data), "checksum64": checksum64(data)}
	switch encoding {
	case "base64":
		result["data_base64"] = base64.StdEncoding.EncodeToString(data)
	case "hex":
		result["data_hex"] = hex.EncodeToString(data)
	case "utf8":
		if !utf8.Valid(data) {
			return nil, errors.New("data is not valid UTF-8")
		}
		result["data_utf8"] = string(data)
	default:
		return nil, fmt.Errorf("unsupported encoding %q", encoding)
	}
	return result, nil
}

func decodeDirectData(dataBase64, dataHex, dataUTF8 string, fill *fillSpec) ([]byte, error) {
	sources := 0
	if dataBase64 != "" {
		sources++
	}
	if dataHex != "" {
		sources++
	}
	if dataUTF8 != "" {
		sources++
	}
	if fill != nil {
		sources++
	}
	if sources > 1 {
		return nil, errors.New("provide only one data source")
	}
	if dataBase64 != "" {
		return base64.StdEncoding.DecodeString(dataBase64)
	}
	if dataHex != "" {
		return hex.DecodeString(dataHex)
	}
	if dataUTF8 != "" {
		return []byte(dataUTF8), nil
	}
	if fill != nil {
		return fillBytes(fill)
	}
	return []byte{}, nil
}

func fillBytes(fill *fillSpec) ([]byte, error) {
	length := uint64(fill.Length)
	if length == 0 {
		return nil, errors.New("fill length must be greater than zero")
	}
	if length > uint64(int(^uint(0)>>1)) {
		return nil, fmt.Errorf("fill length %d is too large for this platform", length)
	}
	mode := fill.Mode
	if mode == "" {
		mode = "zero"
	}
	data := make([]byte, int(length))
	switch mode {
	case "zero":
		return data, nil
	case "value":
		for i := range data {
			data[i] = byte(fill.Value)
		}
		return data, nil
	default:
		return nil, fmt.Errorf("unsupported fill mode %q", mode)
	}
}

func (a *App) inputBytesLocked(dataBase64, dataHex, dataUTF8, bufferName string, bufferOffset, length uint64) ([]byte, error) {
	directSources := 0
	if dataBase64 != "" {
		directSources++
	}
	if dataHex != "" {
		directSources++
	}
	if dataUTF8 != "" {
		directSources++
	}
	if bufferName != "" {
		directSources++
	}
	if directSources > 1 {
		return nil, errors.New("provide only one data source")
	}
	if bufferName == "" {
		return decodeDirectData(dataBase64, dataHex, dataUTF8, nil)
	}
	buffer, err := a.bufferLocked(bufferName)
	if err != nil {
		return nil, err
	}
	data, err := sliceRange(buffer.Data, bufferOffset, length, true)
	if err != nil {
		return nil, err
	}
	copyData := append([]byte(nil), data...)
	return copyData, nil
}

func sliceRange(data []byte, offset, length uint64, restWhenZero bool) ([]byte, error) {
	if offset > uint64(len(data)) {
		return nil, fmt.Errorf("offset %d exceeds length %d", offset, len(data))
	}
	if length == 0 && restWhenZero {
		length = uint64(len(data)) - offset
	}
	if length > uint64(len(data))-offset {
		return nil, fmt.Errorf("range offset=%d length=%d exceeds length %d", offset, length, len(data))
	}
	return data[int(offset):int(offset+length)], nil
}
