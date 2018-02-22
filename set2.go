package cryptopals

import "crypto/aes"

// PKCS7Padding returns the provided input padded up to paddingLen.
func PKCS7Padding(in []byte, paddingLen int) []byte {
	o := make([]byte, len(in))
	copy(o, in)
	if len(in) > paddingLen {
		return o
	}
	for len(o) < paddingLen {
		o = append(o, '\x04')
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
	// TODO: ensure len is multiple of blocksize
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
