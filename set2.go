package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"fmt"
	"io"
	mathrand "math/rand"
)

// PKCS7PaddingBlockSize returns the provided input padded to the given block size.
func PKCS7PaddingBlockSize(in []byte, blockSize int) []byte {
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
	UnkownBlockMode BlockMode = iota
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
	content = PKCS7PaddingBlockSize(content, aes.BlockSize)
	fmt.Printf("%q\n", content)
	if mathrand.Intn(2) == 0 {
		fmt.Printf("CBC ")
		return EncryptAESCBC(content, key, iv)
	}
	fmt.Printf("ECB ")
	return EncryptAESECB(content, key)
}

// DetectECBorCBC
func DetectECBorCBC(in []byte) BlockMode {
	return UnkownBlockMode
}
