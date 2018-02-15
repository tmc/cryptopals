package cryptopals

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"testing"
	"unicode"

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
	var options []string
	for i := 0; i < 255; i++ {
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
		unPrintable := false
		for _, c := range string(d) {
			if !unicode.IsPrint(c) {
				unPrintable = true
			}
		}
		if !unPrintable {
			options = append(options, string(d))
		}
	}
	sort.SliceStable(options, func(i, j int) bool {
		return NTopEnglish(options[i]) > NTopEnglish(options[j])
	})
	// print string with highest score
	t.Logf("%v %v", NTopEnglish(options[0]), options[0])
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
