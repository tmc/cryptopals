package cryptopals

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"reflect"
	"testing"
)

func ExamplePKCS7Padding() {
	fmt.Printf("%q", PKCS7PaddingBlockSize([]byte("YELLOW SUBMARINE"), 20))
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
			pt := PKCS7PaddingBlockSize(tt.args.plaintext, aes.BlockSize)
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
