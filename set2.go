package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	mathrand "math/rand"
	"net/url"
	"strings"
)

type EncryptionFunc func([]byte) ([]byte, error)

// PKCS7Padding returns the provided input padded to the given block size.
func PKCS7Padding(in []byte, blockSize int) []byte {
	n := blockSize - len(in)%blockSize
	o := make([]byte, len(in))
	copy(o, in)
	for i := 0; i < n; i++ {
		o = append(o, byte(n))
	}
	return o
}

// EncryptAESCBC encrypts the given plaintext with the given key in CBC mode.
func EncryptAESCBC(plaintext, key, iv []byte) ([]byte, error) {
	if plaintext == nil || key == nil {
		return nil, ErrEmpty
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err

	}
	if len(plaintext)%aes.BlockSize != 0 {
		panic("plaintext must be a multiple of the block size")
	}
	ciphertext := make([]byte, len(plaintext))
	n := len(ciphertext) / c.BlockSize()
	previousCiphertext := iv
	for i := 0; i < n; i++ {
		// first place the plaintext xor'd with the previous ciphertext into the destination
		for j := 0; j < c.BlockSize(); j++ {
			idx := (i * c.BlockSize()) + j
			ciphertext[idx] = plaintext[idx] ^ previousCiphertext[j]
		}
		// replace block in ciphertext with result of the encryption.
		c.Encrypt(ciphertext[i*c.BlockSize():], ciphertext[i*c.BlockSize():])
		previousCiphertext = ciphertext[i*c.BlockSize():]
	}
	return ciphertext, nil
}

// DecryptAESCBC decrypts the given ciphertext with the given key in CBC mode.
func DecryptAESCBC(ciphertext, key, iv []byte) ([]byte, error) {
	if ciphertext == nil || key == nil {
		return nil, ErrEmpty
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// TODO: ensure len is multiple of blocksize
	plaintext := make([]byte, len(ciphertext))
	n := len(plaintext) / c.BlockSize()
	previousCiphertext := iv
	for i := 0; i < n; i++ {
		// replace block in plaintext with result of the decryption.
		c.Decrypt(plaintext[i*c.BlockSize():], ciphertext[i*c.BlockSize():])
		// first decrypt block and then xor with the previous block
		for j := 0; j < c.BlockSize(); j++ {
			idx := (i * c.BlockSize()) + j
			plaintext[idx] = plaintext[idx] ^ previousCiphertext[j]
		}
		previousCiphertext = ciphertext[i*c.BlockSize():]
	}
	return plaintext, nil
}

// RandomAESKey generates a random aes key.
func RandomAESKey() []byte {
	result := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, result); err != nil {
		panic(err)
	}
	return result
}

type BlockMode int

const (
	UnknownBlockMode BlockMode = iota
	ECBBlockMode
	CBCBlockMode
)

// EncryptAESWithRandomKey
func EncryptAESWithRandomKey(plaintext []byte) ([]byte, error) {
	n := mathrand.Intn(5) + 5
	content := make([]byte, 0, len(plaintext)+2*n)
	key := RandomAESKey()
	iv := RandomAESKey()
	toAdd := bytes.Repeat([]byte{'\x04'}, n)

	content = append(content, toAdd...)
	content = append(content, plaintext...)
	content = append(content, toAdd...)
	copy(content, toAdd)
	content = PKCS7Padding(content, aes.BlockSize)
	if mathrand.Intn(2) == 0 {
		return EncryptAESCBC(content, key, iv)
	}
	return EncryptAESECB(content, key)
}

// DetectECBorCBC is our oracle for detecting ECB vs CBC.
func DetectECBorCBC(in []byte) BlockMode {
	d, err := MinHammingDistance(in, aes.BlockSize)
	if err != nil {
		return UnknownBlockMode
	}
	if d == 0 {
		return ECBBlockMode
	}
	return CBCBlockMode
}

var arbitraryECBKey []byte

var contentToAppend = []byte(`Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg` +
	`aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq` +
	`dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg` +
	`YnkK`)

// EncryptAESECBUnknownButConsistentKey
func EncryptAESECBUnknownButConsistentKey(plaintext []byte) ([]byte, error) {
	if arbitraryECBKey == nil {
		arbitraryECBKey = RandomAESKey()
	}
	return EncryptAESECB(plaintext, arbitraryECBKey)
}

// DecryptAESECBUnknownButConsistentKey
func DecryptAESECBUnknownButConsistentKey(ciphertext []byte) ([]byte, error) {
	if arbitraryECBKey == nil {
		arbitraryECBKey = RandomAESKey()
	}
	return DecryptAESECB(ciphertext, arbitraryECBKey)
}

// EncryptAESECBUnknownButConsistentKeyWithSuffix
func EncryptAESECBUnknownButConsistentKeyWithSuffix(plaintext []byte) ([]byte, error) {
	if arbitraryECBKey == nil {
		arbitraryECBKey = RandomAESKey()
	}
	contents := make([]byte, base64.StdEncoding.DecodedLen(len(contentToAppend)))
	if _, err := base64.StdEncoding.Decode(contents, contentToAppend); err != nil {
		return nil, err
	}
	plaintext = append(plaintext, contents...)
	return EncryptAESECB(plaintext, arbitraryECBKey)
}

// DetermineBlockSize returns the block sie of the given encryption function in bytes.
func DetermineBlockSize(fn EncryptionFunc) (int, error) {
	// encrypt 1024 extra bits and check for ciphertext block matches
	in := bytes.Repeat([]byte{'A'}, 128)
	output, err := fn(in)
	if err != nil {
		return -1, err
	}
	for i := 2; i < 1024; i = i * 2 {
		c := bytes.Compare(output[:i], output[i:i*2])
		if c == 0 {
			return i, nil
		}
	}
	return -1, ErrNotFound
}

func parseKV(i string) (map[string]string, error) {
	v, err := url.ParseQuery(i)
	result := make(map[string]string)
	for k := range v {
		result[k] = v.Get(k)
	}
	return result, err
}

func profileFor(email string) map[string]string {
	u := url.Values{}
	u.Set("uid", "10")
	u.Set("email", email)
	u.Set("role", "user")
	v, err := parseKV(u.Encode())
	if err != nil {
		panic(err)
	}
	return v
}

func encodeProfile(profile map[string]string) string {
	var parts []string
	for _, k := range []string{"email", "uid", "role"} {
		parts = append(parts, fmt.Sprintf("%s=%s", k, profile[k]))
	}
	return strings.Join(parts, "&")
}

func encryptProfile(profile map[string]string) string {
	e := encodeProfile(profile)
	enc, err := EncryptAESECBUnknownButConsistentKey([]byte(e))
	if err != nil {
		return err.Error()
	}
	return string(enc)
}

func decryptProfile(profile string) (map[string]string, error) {
	dec, err := DecryptAESECBUnknownButConsistentKey([]byte(profile))
	if err != nil {
		return nil, err
	}
	p, err := parseKV(string(dec))
	if err != nil {
		return nil, err
	}
	return p, nil
}
