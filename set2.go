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

	"github.com/pkg/errors"
)

const MaxPrefix = 1024 // only check for up to this size of fixed prefix in unknown ECB encryption function.

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
	padded := PKCS7Padding(plaintext, c.BlockSize())
	ciphertext := make([]byte, len(padded))
	n := len(ciphertext) / c.BlockSize()
	previousCiphertext := iv
	for i := 0; i < n; i++ {
		// first place the plaintext xor'd with the previous ciphertext into the destination
		for j := 0; j < c.BlockSize(); j++ {
			idx := (i * c.BlockSize()) + j
			ciphertext[idx] = padded[idx] ^ previousCiphertext[j]
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
	if len(ciphertext)%aes.BlockSize != 0 {
		panic("ciphertext must be a multiple of the block size")
	}
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
	paddingLen := int(plaintext[len(plaintext)-1])
	return plaintext[:len(plaintext)-paddingLen], nil
}

// RandomAESKey generates a random aes key.
func RandomAESKey() []byte {
	return RandomNBytes(aes.BlockSize)
}

// RandomBytes generates a random set of bytes.
func RandomNBytes(n int) []byte {
	result := make([]byte, n)
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

var arbitraryCBCKey []byte

// EncryptAESCBCUnknownButConsistentKey
func EncryptAESCBCUnknownButConsistentKey(plaintext []byte) ([]byte, error) {
	if arbitraryCBCKey == nil {
		arbitraryCBCKey = RandomAESKey()
	}
	return EncryptAESCBC(plaintext, arbitraryCBCKey, bytes.Repeat([]byte{byte(0x0)}, aes.BlockSize))
}

// DecryptAESCBCUnknownButConsistentKey
func DecryptAESCBCUnknownButConsistentKey(ciphertext []byte) ([]byte, error) {
	if arbitraryCBCKey == nil {
		arbitraryCBCKey = RandomAESKey()
	}
	return DecryptAESCBC(ciphertext, arbitraryCBCKey, bytes.Repeat([]byte{byte(0x0)}, aes.BlockSize))
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

var arbitraryECBPrefix []byte

// EncryptAESECBUnknownButConsistentKeyWithPrefixAndSuffix
func EncryptAESECBUnknownButConsistentKeyWithPrefixAndSuffix(plaintext []byte) ([]byte, error) {
	if arbitraryECBKey == nil {
		arbitraryECBKey = RandomAESKey()
	}
	if arbitraryECBPrefix == nil {
		n := mathrand.Intn(128)
		arbitraryECBPrefix = RandomNBytes(n)
	}
	suffix := make([]byte, base64.StdEncoding.DecodedLen(len(contentToAppend)))
	if _, err := base64.StdEncoding.Decode(suffix, contentToAppend); err != nil {
		return nil, err
	}
	p := make([]byte, len(arbitraryECBPrefix))
	copy(p, arbitraryECBPrefix)
	p = append(p, plaintext...)
	p = append(p, suffix...)
	return EncryptAESECB(p, arbitraryECBKey)
}

// DetermineBlockSize returns the block size of the given encryption function in bytes.
func DetermineBlockSize(fn EncryptionFunc) (int, error) {
	buf := []byte{}
	c, err := fn(buf)
	if err != nil {
		return -1, err
	}
	ctlen := func(b []byte) int {
		c, _ := fn(b)
		return len(c)
	}
	for i := 0; ctlen(buf) == len(c); i++ {
		buf = append(buf, 'A')
	}
	return ctlen(buf) - len(c), nil
}

// DeterminePrefixSize returns the size necessary to include in a plaintext prefix to have the next bytes at the start of a new ECB block.
func DeterminePrefixSize(fn EncryptionFunc) (n, blocks int, err error) {
	blocksize, err := DetermineBlockSize(fn)
	if err != nil {
		return -1, -1, errors.Wrap(err, "DetermineBlockSize")
	}
	for i := 0; i < MaxPrefix; i++ {
		// TODO: this assumes the prefix doesn't end in A
		k := (2 * blocksize) + i
		in := bytes.Repeat([]byte{'A'}, k)
		in = append(in, bytes.Repeat([]byte{'B'}, blocksize)...)
		output, err := fn(in)
		if err != nil {
			return -1, -1, err
		}
		nr, bs, err := NumRepeatingBlocks(output, blocksize)
		if err != nil {
			return -1, -1, errors.Wrap(err, "NumRepeatingBlocks")
		}
		if nr > 0 {
			return i, bs, nil
		}
	}
	return -1, -1, ErrNotFound
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

func DecryptAESECBSuffix(encryptionFn EncryptionFunc) ([]byte, error) {

	// determine block size
	blockSize, err := DetermineBlockSize(encryptionFn)
	if err != nil {
		return nil, err
	}

	encryptedAs, err := encryptionFn(bytes.Repeat([]byte(`A`), blockSize*3))
	if err != nil {
		return nil, err
	}

	// determine that this is ECB
	blockMode := DetectECBorCBC(encryptedAs)
	if blockMode != ECBBlockMode {
		return nil, errors.New("not ECB")
	}

	// determine prefix needed
	prefixLen, prefixBlocks, err := DeterminePrefixSize(encryptionFn)
	if err != nil {
		return nil, errors.Wrap(err, "DeterminePrefixSize")
	}

	basePrefix := bytes.Repeat([]byte(`X`), prefixLen)
	nothingEncrypted, err := encryptionFn(basePrefix)
	if err != nil {
		return nil, err
	}

	in := bytes.Repeat([]byte(`A`), blockSize)
	blockMap := make(map[string]byte)

	nBlocks := len(nothingEncrypted) / blockSize

	var plaintext []byte

	for block := prefixBlocks; block < nBlocks; block++ {
		for i := 0; i < blockSize; i++ {
			k := prefixBlocks * blockSize
			for j := 0; j < 256; j++ {
				in[len(in)-1] = byte(j)

				enc, err := encryptionFn(append(basePrefix, in...))
				key := fmt.Sprintf("%x", enc[k:k+blockSize])
				if err != nil {
					return nil, err
				}
				blockMap[key] = byte(j)
			}

			enc, err := encryptionFn(append(basePrefix, in[:blockSize-1-(i%blockSize)]...))
			if err != nil {
				return nil, err
			}
			key := fmt.Sprintf("%x", enc[block*blockSize:(block+1)*blockSize])

			b := blockMap[key]
			in[len(in)-1] = b
			in = append(in[1:], 'x')
			plaintext = append(plaintext, b)
		}
	}
	return plaintext, nil
}

// StripPKCS7Padding returns an unpadded version of the input or a non-nil error if the PKCS7 padding is invalid.
func StripPKCS7Padding(in []byte, blockSize int) ([]byte, error) {
	if len(in) == 0 {
		return nil, ErrEmpty
	}
	if len(in)%blockSize != 0 {
		return nil, ErrMismatchedLength
	}
	npad := in[len(in)-1]
	if int(npad) > blockSize {
		return nil, ErrInvalidPadding
	}
	padding := in[len(in)-int(npad):]

	for _, c := range padding {
		if c != npad {
			return nil, ErrInvalidPadding
		}
	}
	return in[:len(in)-int(npad)], nil
}

func challenge16Encrypt(in []byte) ([]byte, error) {
	s := "comment1=cooking%20MCs;userdata="
	s += url.QueryEscape(string(in))
	s += ";comment2=%20like%20a%20pound%20of%20bacon"
	return EncryptAESCBCUnknownButConsistentKey([]byte(s))
}

func challenge16Decrypt(ciphertext []byte) ([]byte, error) {
	return DecryptAESCBCUnknownButConsistentKey([]byte(ciphertext))
}
