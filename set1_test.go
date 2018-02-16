package cryptopals

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestHex2Base64(t *testing.T) {
	tests := []struct {
		name    string
		in      []byte
		want    []byte
		wantErr bool
	}{
		{"nils", nil, nil, false},
		{"empty", []byte(""), []byte(""), false},
		{"example",
			[]byte("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"),
			[]byte("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"), false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Hex2Base64(tt.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("Hex2Base64() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !cmp.Equal(got, tt.want, cmpopts.EquateEmpty()) {
				t.Errorf("Hex2Base64() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestXORHexSlices(t *testing.T) {
	type args struct {
		a []byte
		b []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{"nils", args{nil, nil}, nil, false},
		{"example", args{
			[]byte("1c0111001f010100061a024b53535009181c"),
			[]byte("686974207468652062756c6c277320657965"),
		},
			[]byte("746865206b696420646f6e277420706c6179"),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := XORHexSlices(tt.args.a, tt.args.b)
			if (err != nil) != tt.wantErr {
				t.Errorf("XORHexSlices() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !cmp.Equal(got, tt.want, cmpopts.EquateEmpty()) {
				t.Errorf("XORHexSlices() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestChallenge3(t *testing.T) {
	in := []byte("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	key, plaintext, err := SolveSingleByteXOR(in)
	if err != nil {
		t.Error(err)
	}
	// print string with highest score
	t.Logf("%v %v %v", key, NTopEnglish(plaintext), plaintext)
}

func TestChallenge4(t *testing.T) {
	f, err := os.Open("4.txt")
	if err != nil {
		t.Error(err)
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	var lines [][]byte
	for s.Scan() {
		lines = append(lines, []byte(s.Text()))
	}
	if s.Err() != nil {
		t.Error(s.Err())
	}

	type option struct {
		s string
		o string
	}
	var options []option
	for _, in := range lines {
		for i := 0; i < 255; i++ {
			//t.Logf("%v %v", lineNo, i)
			x := []byte(fmt.Sprintf("%x", bytes.Repeat([]byte{byte(i)}, hex.DecodedLen(len(in)))))
			o, err := XORHexSlices(in, x)
			if err != nil {
				continue
			}
			d := make([]byte, hex.DecodedLen(len(in)))
			_, err = hex.Decode(d, o)
			if err != nil {
				continue
			}
			options = append(options, option{string(d), string(in)})
		}
	}
	sort.SliceStable(options, func(i, j int) bool {
		return NTopEnglish(options[i].s) > NTopEnglish(options[j].s)
		//return PercentLetters(options[i]) > PercentLetters(options[j])
	})
	// print string with highest score
	t.Logf("%v %q", NTopEnglish(options[0].s), options[0])
	/*
		for _, o := range options[:10] {
			s := o.s
			t.Logf("%v %v %v %v %q\n", NTopEnglish(s), PercentLetters(s), PercentCommonEnglish(s), len(s), s)
		}
	*/
}

func TestRepeatingXOR(t *testing.T) {
	type args struct {
		plaintext []byte
		key       []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{"nils", args{nil, nil}, nil, false},
		{"example", args{[]byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"), []byte("ICE")},
			[]byte("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RepeatingXOR(tt.args.plaintext, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("RepeatingXOR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !cmp.Equal(got, tt.want, cmpopts.EquateEmpty()) {
				t.Errorf("RepeatingXOR() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHammingDistance(t *testing.T) {
	type args struct {
		a []byte
		b []byte
	}
	tests := []struct {
		name    string
		args    args
		want    int
		wantErr bool
	}{
		{"nils", args{nil, nil}, 0, false},
		{"one nil", args{nil, []byte("x")}, 0, true},
		{"zero", args{[]byte("a"), []byte("a")}, 0, false},
		{"example", args{[]byte("this is a test"), []byte("wokka wokka!!!")}, 37, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := HammingDistance(tt.args.a, tt.args.b)
			if (err != nil) != tt.wantErr {
				t.Errorf("HammingDistance() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("HammingDistance() = %v, want %v", got, tt.want)
			}
		})
	}
}

type KeyDist struct {
	N int
	D float64
}

func RepeatingXORKeySizes(ciphertext []byte) ([]KeyDist, error) {
	var distances []KeyDist
	// TODO: be flexible in size
	for keysize := 2; keysize < 40; keysize++ {
		bufA := ciphertext[:keysize]
		bufB := ciphertext[keysize : 2*keysize]
		bufC := ciphertext[2*keysize : 3*keysize]
		bufD := ciphertext[3*keysize : 4*keysize]
		//spew.Dump(bufA, bufB, bufC, bufD, ciphertext)
		hd1, err := HammingDistance(bufA, bufB)
		if err != nil {
			return nil, err
		}
		hd2, err := HammingDistance(bufC, bufD)
		if err != nil {
			return nil, err
		}
		hd3, err := HammingDistance(bufA, bufC)
		if err != nil {
			return nil, err
		}
		hd4, err := HammingDistance(bufB, bufD)
		if err != nil {
			return nil, err
		}
		hd := (hd1 + hd2 + hd3 + hd4) / 4.0
		d := float64(hd) / float64(keysize)
		distances = append(distances, KeyDist{keysize, d})
	}
	sort.SliceStable(distances, func(i, j int) bool {
		return distances[i].D < distances[j].D
	})
	return distances, nil
}

func GuessXORKeySize(ciphertext []byte) (int, error) {
	sizes, err := RepeatingXORKeySizes(ciphertext)
	if err != nil {
		return 0, err
	}
	return sizes[0].N, nil
}

func TestChallenge6(t *testing.T) {
	encoded, err := ioutil.ReadFile("6.txt")
	if err != nil {
		t.Fatal(err)
	}
	contents := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	// un-base64
	if _, err := base64.StdEncoding.Decode(contents, encoded); err != nil {
		t.Fatal(err)
	}
	keysizes, err := RepeatingXORKeySizes(contents)
	if err != nil {
		t.Error(err)
	}

	var results []string
	// check top 5 key sizes
	for _, keysize := range keysizes[:5] {
		t.Logf("trying keysize=%v", keysize)
		plaintext, err := SolveRepeatingXOR(contents, keysize.N)
		if err != nil {
			t.Error(err)
		}
		results = append(results, string(plaintext))
	}

	sort.SliceStable(results, func(i, j int) bool {
		return NTopEnglish(results[i]) > NTopEnglish(results[j])
	})
	t.Logf("%v", results[0])
}

func TestChallenge7(t *testing.T) {
	encoded, err := ioutil.ReadFile("7.txt")
	if err != nil {
		t.Fatal(err)
	}
	contents := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	if _, err := base64.StdEncoding.Decode(contents, encoded); err != nil {
		t.Fatal(err)
	}
	plaintext, err := DecryptAESECB(contents, []byte("YELLOW SUBMARINE"))
	t.Logf("%q", plaintext)
}
