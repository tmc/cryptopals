package cryptopals

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/bits"
	"sort"

	"github.com/pkg/errors"
)

var (
	// ErrMismatchedLengths is returned when parameters violate a length-matching invariant.
	ErrMismatchedLengths = errors.New("mismatched lengths")
	// ErrEmpty is returned when a necessary value has not been provided.
	ErrEmpty = errors.New("empty")
	// ErrNotFound is returned when a searched-for value cannot be determined.
	ErrNotFound = errors.New("not found")
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

// RepeatingXOR returns the hex-encoded result of repeated XOR application of key to plaintext.
func RepeatingXOR(plaintext, key []byte) ([]byte, error) {
	c := make([]byte, len(plaintext))
	for i := range plaintext {
		c[i] = plaintext[i] ^ key[i%len(key)]
	}
	return []byte(hex.EncodeToString(c)), nil
}

// HammingDistance computes the number of bits that differ between a and b.
func HammingDistance(a, b []byte) (int, error) {
	n := 0
	if len(a) != len(b) {
		return 0, ErrMismatchedLengths
	}

	for i := range a {
		d := a[i] ^ b[i]
		n += bits.OnesCount(uint(d))
	}
	return n, nil
}

// SolveSingleByteXOR attempts to recover plaintext from a single-byte xor encrypted ciphertext.
func SolveSingleByteXOR(in []byte) (key byte, plaintext string, err error) {
	type option struct {
		key       byte
		plaintext string
	}
	var options []option
	for i := 0; i < 255; i++ {
		x := []byte(fmt.Sprintf("%x", bytes.Repeat([]byte{byte(i)}, hex.DecodedLen(len(in)))))
		o, err := XORHexSlices(in, x)
		if err != nil {
			return 0, "", errors.Wrap(err, "issue xoring slices")
		}
		d := make([]byte, hex.DecodedLen(len(in)))
		_, err = hex.Decode(d, o)
		if err != nil {
			return 0, "", errors.Wrap(err, "issue decoding hex")
		}
		options = append(options, option{byte(i), string(d)})
	}
	sort.SliceStable(options, func(i, j int) bool {
		return NTopEnglish(options[i].plaintext) > NTopEnglish(options[j].plaintext)
	})
	if len(options) == 0 {
		return 0, "", ErrEmpty
	}
	/*
		for _, o := range options[:5] {
			fmt.Printf("%v - %v - %q\n", PercentCommonEnglish(o.plaintext), NTopEnglish(o.plaintext), o.plaintext)
		}
	*/
	return options[0].key, options[0].plaintext, nil
}

// SolveRepeatingXOR attempts to recover plaintext from a given repeated-xor encrypted ciphertext and given key size.
func SolveRepeatingXOR(ciphertext []byte, keysize int) ([]byte, error) {
	transposedBlocks := make([][]byte, keysize)
	for i := 0; i < len(ciphertext); i++ {
		j := i % keysize
		transposedBlocks[j] = append(transposedBlocks[j], ciphertext[i])
	}
	var key []byte
	for _, block := range transposedBlocks {
		blockHex := []byte(hex.EncodeToString(block))
		k, _, err := SolveSingleByteXOR(blockHex)
		if err != nil {
			return nil, err
		}
		key = append(key, k)
	}
	decrypted, err := RepeatingXOR(ciphertext, key)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, hex.DecodedLen(len(decrypted)))
	if _, err := hex.Decode(plaintext, decrypted); err != nil {
		return nil, err
	}
	return plaintext, nil
}

// DecryptAESECB decrypts the given ciphertext with the given key in ECB mode.
func DecryptAESECB(ciphertext, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// TODO: ensure len is multiple of blocksize
	plaintext := make([]byte, len(ciphertext))
	n := len(ciphertext) / c.BlockSize()
	for i := 0; i < n; i++ {
		c.Decrypt(plaintext[i*c.BlockSize():], ciphertext[i*c.BlockSize():])
	}
	paddingLen := int(plaintext[len(plaintext)-1])
	return plaintext[:len(plaintext)-paddingLen], nil
}

// EncryptAESECB decrypts the given ciphertext with the given key in ECB mode.
func EncryptAESECB(plaintext, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padded := PKCS7Padding(plaintext, c.BlockSize())
	ciphertext := make([]byte, len(padded))
	n := len(padded) / c.BlockSize()
	for i := 0; i < n; i++ {
		c.Encrypt(ciphertext[i*c.BlockSize():], padded[i*c.BlockSize():])
	}
	return ciphertext, nil
}

// HammingDistances returns a list of hamming distances between the blocks in the provided byte slice.
func HammingDistances(in []byte, blocksize int) ([]int, error) {
	var results []int

	// TODO: ensure len is multiple of blocksize
	var blocks [][]byte
	for i := 0; i < len(in); i += blocksize {
		blocks = append(blocks, in[i:i+blocksize])
	}
	for i := 0; i < len(blocks); i++ {
		for j := 0; j < len(blocks); j++ {
			if i == j {
				continue
			}
			d, err := HammingDistance(blocks[i], blocks[j])
			if err != nil {
				return nil, err
			}
			results = append(results, d)
		}
	}
	return results, nil
}

// MinHammingDistance returns the minimum hamming distance between two blocks.
func MinHammingDistance(in []byte, blocksize int) (int, error) {
	scores, err := HammingDistances(in, blocksize)
	if err != nil {
		return -1, nil
	}
	// sort scores
	sort.SliceStable(scores, func(i, j int) bool {
		return scores[i] < scores[j]
	})
	return scores[0], nil
}
