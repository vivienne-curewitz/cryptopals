package xor

import (
	"encoding/hex"
	"log"
	"unicode"
)

var letterFrequencies = map[rune]float64{
	'a': .0817, 'b': .0149, 'c': .0278, 'd': .0425, 'e': .1270,
	'f': .0223, 'g': .0202, 'h': .0609, 'i': .0697, 'j': .0015,
	'k': .0077, 'l': .0403, 'm': .0241, 'n': .0675, 'o': .0751,
	'p': .0193, 'q': .0010, 'r': .0599, 's': .0633, 't': .0906,
	'u': .0276, 'v': .0098, 'w': .0236, 'x': .0015, 'y': .0197,
	'z': .0007, ' ': .1300,
}

func scoreText(text string) float64 {
	var score float64
	for _, r := range text {
		score += letterFrequencies[unicode.ToLower(r)]
	}
	return score
}

func decryptXORInput(hexStr string) (uint8, float64, string) {
	hb, err := hex.DecodeString(hexStr)
	if err != nil {
		log.Panicf("Could not decode hex string: %s\n", err)
	}
	var bestRune uint8 = 0
	var bestScore float64 = 0
	data := make([]byte, len(hb))
	var i uint8
	const max uint8 = 255
	for i = range max {
		for j := range len(hb) {
			data[j] = hb[j] ^ i
		}
		score := scoreText(string(data))
		if score > bestScore {
			bestRune = i
			bestScore = score
		}
	}
	for j := range len(hb) {
		data[j] = hb[j] ^ bestRune
	}
	return bestRune, bestScore, string(data)
}

func decryptXORInputBytes(hb []byte) (uint8, float64, string) {
	var bestRune uint8 = 0
	var bestScore float64 = 0
	data := make([]byte, len(hb))
	var i uint8
	const max uint8 = 255
	for i = range max {
		for j := range len(hb) {
			data[j] = hb[j] ^ i
		}
		score := scoreText(string(data))
		if score > bestScore {
			bestRune = i
			bestScore = score
		}
	}
	for j := range len(hb) {
		data[j] = hb[j] ^ bestRune
	}
	return bestRune, bestScore, string(data)
}
