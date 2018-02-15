package cryptopals

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

const EnglishLetterFrequenciesTop13 = "ETAOIN SHRDLU"

var highFreqEnglish = regexp.MustCompile(fmt.Sprintf("[%s]", EnglishLetterFrequenciesTop13))

// NTopEnglish returns the number of ocurrencies of common english letters in a string.
func NTopEnglish(s string) int {
	return len(highFreqEnglish.FindAllString(strings.ToUpper(s), -1))
}

func NLetters(s string) int {
	n := 0
	for _, c := range []rune(s) {
		if unicode.IsLetter(c) {
			n++
		}
		if !unicode.IsPrint(c) {
			n--
		}
	}
	return n
}

// PercentCommonEnglish returns the percentage of characters that are appear to be common english letters.
func PercentCommonEnglish(s string) float64 {
	return float64(NTopEnglish(s)) / float64(len([]rune(s)))
}

// PercentLetters
func PercentLetters(s string) float64 {
	return float64(NLetters(s)) / float64(len([]rune(s)))
}

// LetterFrequencies allows computation of rune frequencies.
type LetterFrequencies map[rune]int

// Write satisfies the io.Writer interface.
func (lf LetterFrequencies) Write(p []byte) (n int, err error) {
	for _, r := range []rune(string(p)) {
		lf[r]++
	}
	return len(p), nil
}

// RuneFreq is a rune,occurance pair.
type RuneFreq struct {
	r rune
	n int
}

// TopN returns the top n printable runes by frequency.
func (lf LetterFrequencies) TopN(n int) ([]rune, error) {
	result := make([]rune, n)

	runes := make([]RuneFreq, len(lf))
	for r := range lf {
		if unicode.IsPrint(r) {
			runes = append(runes, RuneFreq{r, lf[r]})
		}
	}
	sort.SliceStable(runes, func(i, j int) bool {
		return runes[i].n > runes[j].n
	})
	if len(runes) == 0 {
		return nil, ErrEmpty
	}
	for i := range result {
		if i < len(runes)-1 {
			result[i] = runes[i].r
		} else {
			r := runes[len(runes)-1].r
			result[i] = r
		}
	}
	return result, nil
}

func LetterFrequenciesFromString(s string, n int) ([]rune, error) {
	lf := make(LetterFrequencies)
	lf.Write([]byte(s))
	return lf.TopN(n)
}
