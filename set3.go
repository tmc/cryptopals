package cryptopals

import (
	"crypto/aes"
	"encoding/base64"
	"math/rand"
)

var challenge17IV = RandomAESKey()

func challenge17encrypt() ([]byte, error) {
	s := []string{
		"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
	}
	encoded := []byte(s[rand.Intn(len(s))])
	contents := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	if _, err := base64.StdEncoding.Decode(contents, encoded); err != nil {
		return nil, err
	}
	//contents = []byte("YELLOW SUBMARINEA")
	if arbitraryCBCKey == nil {
		arbitraryCBCKey = RandomAESKey()
	}
	return EncryptAESCBC(contents, arbitraryCBCKey, challenge17IV)
}

func challenge17CheckPadding(in []byte, opts ...bool) bool {
	if arbitraryCBCKey == nil {
		arbitraryCBCKey = RandomAESKey()
	}
	dec, err := DecryptAESCBC(in, arbitraryCBCKey, challenge17IV)
	if err != nil {
		return false
	}

	_, err = StripPKCS7Padding(dec, aes.BlockSize)
	return err == nil
}
