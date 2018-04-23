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
		{"example", args{[]byte("exampleplaintext"), exampleKey, bytes.Repeat([]byte{byte(0x0)}, aes.BlockSize)}, []byte(
			"\xf4%\x12\xe1\xe4\x03\x92\x13\xbdD\x9b\xa4\u007f\xaa\x1bt\b\xea\xc4]\xbfSnP\x16Q\x1f\x86\x03W\a\xc6"), false},
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
	var encryptionFn EncryptionFunc = EncryptAESECBUnknownButConsistentKeyWithSuffix

	result, err := DecryptAESECBSuffix(encryptionFn)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("%q\n", result)
	// output:
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

func ExampleChallenge14() {
	// random-prefix | attacker-controlled | target | random-kkey
	var encryptionFn func([]byte) ([]byte, error) = EncryptAESECBUnknownButConsistentKeyWithPrefixAndSuffix
	//var encryptionFn func([]byte) ([]byte, error) = EncryptAESECBUnknownButConsistentKeyWithSuffix
	//var encryptionFn func([]byte) ([]byte, error) = EncryptAESECBUnknownButConsistentKey

	result, err := DecryptAESECBSuffix(encryptionFn)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("%q\n", result)
	// output:
	// "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n\x01\x00\x00\x00\x00\x00"
}

func TestStripPKCS7Padding(t *testing.T) {
	tests := []struct {
		name    string
		args    []byte
		want    []byte
		wantErr bool
	}{
		{"empty", []byte(""), nil, true},
		{"ok",
			[]byte("ICE ICE BABY\x04\x04\x04\x04"),
			[]byte("ICE ICE BABY"),
			false},
		{"bad1",
			[]byte("ICE ICE BABY\x05\x05\x05\x05"),
			nil, true},
		{"bad2",
			[]byte("ICE ICE BABY\x01\x02\x03\x04"),
			nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := StripPKCS7Padding([]byte(tt.args), aes.BlockSize)
			if (err != nil) != tt.wantErr {
				t.Errorf("StripPKCS7Padding() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("StripPKCS7Padding() = %q, want %q", got, tt.want)
			}
			if tt.wantErr {
				return
			}
		})
	}

}

func s2b(s string) string {
	result := ""
	for _, c := range s {
		result = fmt.Sprintf("%s%.8b", result, c)
	}
	return result
}

func sxor(a, b string) string {
	result := []byte{}
	for i := range a {
		result = append(result, a[i]^b[i])
	}
	return string(result)
}

func ExampleChallenge16() {
	// find close chars
	/*
		for i := 0; i < 256; i++ {
			d, _ := HammingDistance([]byte{';'}, []byte{byte(i)})
			if d == 1 {
				fmt.Println(";", string([]byte{byte(i)}))
			}
		}
		// -> 9 is 1 bit away
		for i := 0; i < 256; i++ {
			d, _ := HammingDistance([]byte{'='}, []byte{byte(i)})
			if d == 1 {
				fmt.Println("=", string([]byte{byte(i)}))
			}
		}
		// -> 9 is also 1 bit away
	*/
	// 32
	//prefix := "comment1=cooking%20MCs;userdata="
	// 42
	//suffix := ";comment2=%20like%20a%20pound%20of%20bacon"

	b1 := "AAAAAAAAAAAAAAAA"
	b2 := "9admin9true9AAAA"
	b3 := ";admin=true;AAAA"
	b4 := sxor(b2, b3)

	ct, err := challenge16Encrypt([]byte(b1 + b2))
	if err != nil {
		fmt.Println(err)
	}

	// xor provided and intended with previous block in ciphertext
	b5 := sxor(string(ct[32:48]), b4)
	copy(ct[32:48], []byte(b5))
	result, err := challenge16Decrypt(ct)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("%s\n", result)
	fmt.Println(bytes.Contains(result, []byte(";admin=true;")))
	// output:
	// true
}
