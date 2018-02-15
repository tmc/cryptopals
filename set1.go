package cryptopals

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

var (
	// ErrMismatchedLengths is returned when parameters violate a length-matching invariant.
	ErrMismatchedLengths = errors.New("mismatched lengths")
	// ErrEmpty is returned when a necessary value has not been provided.
	ErrEmpty = errors.New("empty")
)

// Hex2Base64 takes a byte slice of hex-encoded data and produces base64-encoded output.
func Hex2Base64(in []byte) ([]byte, error) {
	hbuf := make([]byte, hex.DecodedLen(len(in)))
	if _, err := hex.Decode(hbuf, in); err != nil {
		return nil, err
	}
	result := new(bytes.Buffer)
	encoder := base64.NewEncoder(base64.StdEncoding, result)
	encoder.Write(hbuf)
	encoder.Close()
	return result.Bytes(), nil
}

// XORHexSlices takes a two byte slices of hex-encoded data and produces the hex-encoded XOR result.
func XORHexSlices(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, ErrMismatchedLengths
	}
	da := make([]byte, hex.DecodedLen(len(a)))
	if _, err := hex.Decode(da, a); err != nil {
		return nil, err
	}
	db := make([]byte, hex.DecodedLen(len(a)))
	if _, err := hex.Decode(db, b); err != nil {
		return nil, err
	}
	result := make([]byte, len(da))
	// perform xor
	for i := range da {
		result[i] = da[i] ^ db[i]
	}
	return []byte(fmt.Sprintf("%x", result)), nil
}
