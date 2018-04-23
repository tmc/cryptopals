package cryptopals

import (
	"crypto/aes"
	"fmt"
	mathrand "math/rand"
)

func decryptLastBlock(c []byte) ([]byte, error) {
	d := make([]byte, len(c))
	copy(d, c)
	p := make([]byte, 16)
	in := make([]byte, 16)
	for i := 0; i < 16; i++ {
		m := len(d) - 1 - i - 16
		n := 15 - i
		for k := 1; k < 256; k++ {
			d[m] = byte(k)
			t := byte(i + 1) // target byte
			if challenge17CheckPadding(d) {
				in[n] = byte(k) ^ t
				p[n] = c[m] ^ in[n]
				for x := 0; x < i+1; x++ {
					d[m+x] = byte(t+1) ^ in[n+x]
				}
				break
			}
		}
	}
	return p, nil
}

func ExampleChallenge17() {
	mathrand.Seed(42)
	exampleChallenge17()
	// output:
	// "000005I go crazy when I hear a cymbal\x00\x00"
}

func exampleChallenge17() {
	c, err := challenge17encrypt()
	if err != nil {
		panic(err)
	}

	nBlocks := len(c) / aes.BlockSize

	var plaintext []byte
	for i := nBlocks - 1; i >= 0; i-- {
		var c1 []byte
		if i == 0 {
			c1 = append(challenge17IV, c[:aes.BlockSize]...)
		} else {
			c1 = c[:(i+1)*aes.BlockSize]
		}
		p, err := decryptLastBlock(c1)
		if err != nil {
			panic(err)
		}
		plaintext = append(p, plaintext...)
	}
	s, _ := StripPKCS7Padding(plaintext, aes.BlockSize)
	fmt.Printf("%q \n", string(s))
}
