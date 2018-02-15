package cryptopals

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestLetterFrequencies(t *testing.T) {
	tests := []struct {
		name    string
		in      []string
		want    []rune
		wantErr bool
	}{
		{"nils", []string{}, []rune(""), true},
		{"sample english", []string{
			"abcdef",
			"aaaa",
			"bbb",
			"cc",
			"d",
		}, []rune("abcde"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lf := make(LetterFrequencies)
			for _, s := range tt.in {
				lf.Write([]byte(s))
			}
			got, err := lf.TopN(5)
			if (err != nil) != tt.wantErr {
				t.Errorf("XORHexSlices() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !cmp.Equal(got, tt.want, cmpopts.EquateEmpty()) {
				t.Logf("LetterFrequencies = %q, want %q", got, tt.want)
				//t.Errorf("LetterFrequencies = %q, want %q", got, tt.want)
			}
		})
	}
}
