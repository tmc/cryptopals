package cryptopals

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"reflect"
	"testing"
)

func ExamplePKCS7Padding() {
	fmt.Printf("%q", PKCS7Padding([]byte("YELLOW SUBMARINE"), 20))
	// output: "YELLOW SUBMARINE\x04\x04\x04\x04"
}

func TestEncryptAESCBC(t *testing.T) {
	exampleKey, _ := hex.DecodeString("6368616e676520746869732070617373")
	type args struct {
		plaintext []byte
		key       []byte
		iv        []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		//{"nils", args{nil, nil, nil}, nil, true},
		{"example", args{[]byte("exampleplaintext"), exampleKey, bytes.Repeat([]byte{byte(0x0)}, aes.BlockSize)}, []byte("\xf4%\x12\xe1\xe4\x03\x92\x13\xbdD\x9b\xa4\u007f\xaa\x1bt"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pt := PKCS7Padding(tt.args.plaintext, aes.BlockSize)
			got, err := EncryptAESCBC(pt, tt.args.key, tt.args.iv)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncryptAESCBC() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("EncryptAESCBC() = %q, want %q", got, tt.want)
			}
			if tt.wantErr {
				return
			}
			d, err := DecryptAESCBC(got, tt.args.key, tt.args.iv)
			if err != nil {
				t.Errorf("DecryptAESCBC() error = %v", err)
				return
			}
			if !reflect.DeepEqual(d, tt.args.plaintext) {
				t.Errorf("DecryptAESCBC() = %q, want %q", got, tt.want)
			}
		})
	}
}

func ExampleDecryptAESCBC() {
	encoded, err := ioutil.ReadFile("testdata/set2/10.txt")
	if err != nil {
		panic(err)
	}
	contents := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	if _, err := base64.StdEncoding.Decode(contents, encoded); err != nil {
		panic(err)
	}
	d, err := DecryptAESCBC(contents, []byte("YELLOW SUBMARINE"), bytes.Repeat([]byte{byte(0x0)}, aes.BlockSize))
	fmt.Printf("%v %q\n", err, d[:aes.BlockSize*3])
	// output:
	// <nil> "I'm back and I'm ringin' the bell \nA rockin' on "
}

func ExampleEncryptAESWithRandomKey() {
	// 41 characters which will guarantee two repeated blocks.
	plaintext := "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	for i := 0; i < 10; i++ {
		b, err := EncryptAESWithRandomKey([]byte(plaintext))
		if err != nil {
			fmt.Println(err)
		}
		h := hex.EncodeToString(b)
		fmt.Printf("%#v %q\n", DetectECBorCBC(b), h)
	}
}

func ExampleChallenge12ByteAtATimeDecryption() {
	var encryptionFn func([]byte) ([]byte, error) = EncryptAESECBUnknownButConsistentKeyWithSuffix
	justAs := bytes.Repeat([]byte(`A`), 128)

	// determine block size
	blockSize, err := DetermineBlockSize(encryptionFn)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("blocksize:", blockSize)

	//paddedAs := PKCS7Padding(justAs, blockSize)
	paddedAs := justAs
	encryptedAs, err := encryptionFn(paddedAs)
	if err != nil {
		fmt.Println(err)
	}

	// determine that this is ECB
	blockMode := DetectECBorCBC(encryptedAs)
	fmt.Println(blockMode)

	nothingEncrypted, err := encryptionFn([]byte{})
	if err != nil {
		fmt.Println(err)
	}
	in := bytes.Repeat([]byte(`A`), blockSize)
	blockMap := make(map[string]byte)

	nBlocks := len(nothingEncrypted) / blockSize
	var plaintext []byte
	for block := 0; block < nBlocks; block++ {
		for i := 0; i < blockSize; i++ {
			for j := 0; j < 256; j++ {
				in[len(in)-1] = byte(j)

				enc, err := encryptionFn(in)
				key := fmt.Sprintf("%x", enc[:blockSize])
				if err != nil {
					fmt.Println(err)
				}
				blockMap[key] = byte(j)
			}

			enc, err := encryptionFn(in[:blockSize-1-(i%blockSize)])
			if err != nil {
				fmt.Println(err)
			}
			key := fmt.Sprintf("%x", enc[block*blockSize:(block+1)*blockSize])

			b := blockMap[key]
			in[len(in)-1] = b
			in = append(in[1:], 'x')
			plaintext = append(plaintext, b)
		}
	}
	fmt.Printf("%q\n", plaintext)

	// output:
	// blocksize: 16
	// ECBBlockMode
	// "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n\x01\x00\x00\x00\x00\x00"
}

func ExampleChallenge13ParseKV() {
	i := "foo=bar&baz=qux&zap=zazzle"
	v, err := parseKV(i)
	if err != nil {
		fmt.Println(err)
	}
	enc, err := json.Marshal(v)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(enc))
	// output:
	// {"baz":"qux","foo":"bar","zap":"zazzle"}
}

func ExampleChallenge13ProfileFor() {
	fmt.Println(encodeProfile(profileFor("foo@bar.com")))
	// output:
	// email=foo@bar.com&uid=10&role=user
}

func ExampleChallenge13ProfileFort() {
	enc := encryptProfile(profileFor("fooAA@bar.com"))
	dec, err := decryptProfile(enc)
	if err != nil {
		fmt.Println(err)
	}
	s := "AAAAAAAAAAadmin" // generates block starting with "admin"
	s2enc := encryptProfile(profileFor(s))
	s3src := "AAAAAAAAA" // produces a full padding block
	s3enc := encryptProfile(profileFor(s3src))

	resultenc := enc[:32] + s2enc[16:32] + s3enc[32:]
	dec, err = decryptProfile(resultenc)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(encodeProfile(dec)))
	// output:
	// email=fooAA@bar.com&uid=10&role=admin
}
