package cryptanalysis

import (
	"cryptopals/xor"
	"fmt"
	"log"
	"math/rand/v2"
	"sort"
)

const capA = 65
const lowerA = 97

var letterFrequencies = map[byte]float64{
	'a': .0817, 'b': .0149, 'c': .0278, 'd': .0425, 'e': .1270,
	'f': .0223, 'g': .0202, 'h': .0609, 'i': .0697, 'j': .0015,
	'k': .0077, 'l': .0403, 'm': .0241, 'n': .0675, 'o': .0751,
	'p': .0193, 'q': .0010, 'r': .0599, 's': .0633, 't': .0906,
	'u': .0276, 'v': .0098, 'w': .0236, 'x': .0015, 'y': .0197,
	'z': .0007,
}

var bigram_frequencies = []string{
	"th", "of", "io",
	"he", "ed", "le",
	"in", "is", "ve",
	"er", "it", "co",
	"an", "al", "me",
	"re", "ar", "de",
	"on", "st", "hi",
	"at", "to", "ri",
	"en", "nt", "ro",
	"nd", "ng", "ic",
	"ti", "se", "ne",
	"es", "ha", "ea",
	"or", "as", "ra",
	"te", "ou", "ce",
}

func make_key_map(key []byte) map[byte]int {
	key_m := make(map[byte]int)
	for i, kb := range key {
		key_m[kb] = i
	}
	return key_m
}

func Substitution_cypher(key []byte, ciphertext []byte) []byte {
	plain := make([]byte, len(ciphertext))
	key_m := make_key_map(key)
	for i, c_letter := range ciphertext {
		kind, exists := key_m[c_letter]
		if !exists {
			plain[i] = c_letter
		}
		plain[i] = byte(kind + capA)
	}
	// log.Printf("Plain text: %s\n", string(plain))
	return plain
}

func Reverse_vigenere(key []byte, ciphertext []byte) []byte {
	plain := make([]byte, len(ciphertext))
	for i, b := range ciphertext {
		shift := key[i%len(key)] - capA
		pb := b - shift
		if pb < capA {
			pb += 26
		}
		plain[i] = pb
	}
	// log.Printf("Plain text: %s\n", string(plain))
	return plain
}

func generateLetterFrequencies(cipher []byte) map[byte]float64 {
	frequency_map := make(map[byte]float64)
	for _, b := range cipher {
		count, exists := frequency_map[b]
		if !exists {
			frequency_map[b] = 1
		} else {
			frequency_map[b] = count + 1
		}
	}
	for k, v := range frequency_map {
		frequency_map[k] = v / float64(len(cipher))
	}
	log.Printf("Frequency map: %v\n", frequency_map)
	return frequency_map
}

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

// A tiny subset of common English bigrams and their relative weights.
// For a production cracker, you would load thousands of quadgrams from a file.
var commonBigrams = map[string]float64{
	"TH": 10.0, "HE": 9.5, "IN": 9.0, "ER": 8.5, "AN": 8.0,
	"RE": 7.5, "ND": 7.0, "AT": 6.5, "ON": 6.0, "NT": 5.5,
}

var commonTrigrams = map[string]float64{
	"THE": 10.0, "AND": 9.0, "THA": 9.5, "ENT": 8.5, "ING": 8.0, "ION": 7.5,
	"TIO": 7.0, "FOR": 6.5, "NDE": 6.0, "HAS": 5.5, "NCE": 5.0,
}

var commonQuadgrams = map[string]float64{
	"TION": 0.31,
	"NTHE": 0.2,
	"THER": 0.24,
	"THAT": 0.21,
	"OFTH": 0.19,
	"FTHE": 0.19,
	"THES": 0.18,
	"WITH": 0.18,
	"INTH": 0.17,
	"ATIO": 0.17,
}

// scoreText evaluates how "English-like" a string is.
func score_text_bigrams(text string) float64 {
	var score float64
	for i := 0; i < len(text)-1; i++ {
		bigram := text[i : i+2]
		if weight, exists := commonBigrams[bigram]; exists {
			score += weight
		}
	}
	return score
}

func score_text_trigrams(text string) float64 {
	var score float64
	for i := 0; i < len(text)-2; i++ {
		bigram := text[i : i+3]
		if weight, exists := commonTrigrams[bigram]; exists {
			score += weight
		}
	}
	return score
}

func score_text_quadgrams(text string) float64 {
	var score float64
	for i := 0; i < len(text)-3; i++ {
		bigram := text[i : i+4]
		if weight, exists := commonQuadgrams[bigram]; exists {
			score += weight * 100
		}
	}
	return score
}

func SortMapByValueDesc(m map[byte]float64) []byte {
	// Step 1: create a slice of key-value pairs
	type kv struct {
		Key byte
		Val float64
	}
	pairs := make([]kv, 0, len(m))
	for k, v := range m {
		pairs = append(pairs, kv{k, v})
	}

	// Step 2: sort the slice by value descending
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].Val > pairs[j].Val // > for descending
	})

	// Step 3: extract the keys in sorted order
	keys := make([]byte, len(pairs))
	for i, p := range pairs {
		keys[i] = p.Key
	}
	return keys
}

// bug somewhere here
// GuessKey runs the hill climbing algorithm to find the best substitution key.
func Guess_key(ciphertext []byte, prev_key []byte) (string, string) {
	currentKey := make([]byte, 26)
	if prev_key == nil {
		frequency := generateLetterFrequencies(ciphertext)
		f_list := SortMapByValueDesc(frequency)
		l_list := SortMapByValueDesc(letterFrequencies)
		for i, b := range f_list {
			letter := l_list[i]
			index := (letter - 97) % 26 // 97 - 123 lowercase letters
			currentKey[index] = b
		}
	} else {
		currentKey = prev_key
	}
	// 1. Start with a random key (shuffled alphabet)
	// currentKey := []byte(alphabet)
	// rand.Shuffle(len(currentKey), func(i, j int) {
	// 	currentKey[i], currentKey[j] = currentKey[j], currentKey[i]
	// })

	// 2. Score the initial random key
	currentPlaintext := Substitution_cypher(currentKey, ciphertext)
	currentScore := score_text_trigrams(string(currentPlaintext))

	// 3. The Hill Climbing Loop
	iterations := 100000
	for i := 0; i < iterations; i++ {
		if i%1000 == 0 {
			fmt.Printf("\r%.2f%% -- Score: %f", float64(i)/float64(iterations)*100, currentScore)
		}
		// Pick two random positions to swap in the key
		pos1 := rand.IntN(26)
		pos2 := rand.IntN(26)

		// Create a mutated key
		newKey := make([]byte, 26)
		copy(newKey, currentKey)
		newKey[pos1], newKey[pos2] = newKey[pos2], newKey[pos1]

		// Decrypt and score with the mutated key
		newPlaintext := Substitution_cypher(newKey, ciphertext)
		newScore := score_text_trigrams(string(newPlaintext)) + score_text_bigrams(string(newPlaintext)) + score_text_quadgrams(string(newPlaintext))

		// If the score improves, keep the new key!
		if newScore >= currentScore {
			currentScore = newScore
			currentKey = newKey
			currentPlaintext = newPlaintext
		}
	}

	return string(currentKey), string(currentPlaintext)
}

// vigenere cracks below
func Kasiski_search(cipher []byte) int {
	// let's assume min key length is 3
	best_length := 0
	best_score := 0
	for i := 3; i < 15; i += 1 {
		shifted := make([]byte, len(cipher)+i)
		copy(shifted[i:], cipher)
		score := 0
		for j := range len(cipher) {
			if cipher[j] == shifted[j] {
				score += 1
			}
		}
		if score > best_score {
			best_score = score
			best_length = i
		}
	}
	return best_length
}

func Vigenere_key_search(cipher []byte, key_len int) []byte {
	buffer_len := len(cipher)/key_len + 1
	buffers := make([][]byte, key_len)
	for i := range key_len {
		buffers[i] = make([]byte, buffer_len)
	}
	for i := range len(cipher) {
		buffers[i%key_len][i/key_len] = cipher[i]
	}
	key := make([]byte, key_len)
	for i, buf := range buffers {
		shift := search_shift(buf)
		key[i] = byte(shift + capA)
	}
	return key
}

func shift_text(buffer []byte, shift int) []byte {
	retval := make([]byte, len(buffer))
	for i, b := range buffer {
		shifted := int(b) - shift
		if shifted < 0 {
			shifted += 26
		}
		retval[i] = byte(shifted)
	}
	return retval
}

func search_shift(buffer []byte) int {
	best_score := 0.0
	best_shift := 0
	for i := range 26 {
		score := xor.ScoreText(string(shift_text(buffer, i)))
		if score > best_score {
			best_score = score
			best_shift = i
		}
	}
	return best_shift
}

// bug somewhere here
// GuessKey runs the hill climbing algorithm to find the best substitution key.
func Guess_key_vignere(ciphertext []byte, prev_key []byte) (string, string) {
	currentKey := prev_key
	currentPlaintext := Reverse_vigenere(currentKey, ciphertext)
	currentScore := score_text_trigrams(string(currentPlaintext)) + score_text_bigrams(string(currentPlaintext)) + score_text_quadgrams(string(currentPlaintext))

	// 3. The Hill Climbing Loop
	iterations := 100000
	for i := 0; i < iterations; i++ {
		if i%1000 == 0 {
			fmt.Printf("\r%.2f%% -- Score: %f", float64(i)/float64(iterations)*100, currentScore)
		}
		// Pick two random positions to swap in the key
		pos1 := rand.IntN(len(currentKey))
		pos2 := rand.IntN(len(currentKey))

		// Create a mutated key
		newKey := make([]byte, len(currentKey))
		copy(newKey, currentKey)
		newKey[pos1], newKey[pos2] = newKey[pos2], newKey[pos1]

		// Decrypt and score with the mutated key
		newPlaintext := Reverse_vigenere(newKey, ciphertext)
		newScore := score_text_trigrams(string(newPlaintext)) + score_text_bigrams(string(newPlaintext)) + score_text_quadgrams(string(newPlaintext))

		// If the score improves, keep the new key!
		if newScore >= currentScore {
			currentScore = newScore
			currentKey = newKey
			currentPlaintext = newPlaintext
		}
	}

	return string(currentKey), string(currentPlaintext)
}
