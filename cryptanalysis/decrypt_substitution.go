package cryptanalysis

import (
	"log"
	oldrand "math/rand"
	"math/rand/v2"
)

const capA = 65
const lowerA = 97

func make_key_map(key []byte) map[byte]int {
	key_m := make(map[byte]int)
	for i, kb := range key {
		key_m[kb] = i
	}
	return key_m
}

func substitution_cypher(key []byte, ciphertext []byte) {
	plain := make([]byte, len(ciphertext))
	key_m := make_key_map(key)
	for i, c_letter := range ciphertext {
		kind, exists := key_m[c_letter]
		if !exists {
			plain[i] = c_letter
		}
		plain[i] = byte(kind + capA)
	}
	log.Printf("Plain text: %s\n", string(plain))
}

func polymorphic_substitution(key []byte, ciphertext []byte, seed uint64) {
	plain := make([]byte, len(ciphertext))

	source := rand.NewPCG(seed, 0)
	r := rand.New(source)
	key_m := make_key_map(key)
	oldrand.Seed(int64(seed))
	for i, b := range ciphertext {
		index := key_m[b]
		rI := r.Uint64() % uint64(len(key))
		// rI := oldrand.Uint64() % uint64(len(key))
		nIndex := index - int(rI)
		if nIndex < 0 {
			nIndex += 26
		}
		plain[i] = key[nIndex]
	}
	log.Printf("Plain text: %s\n", string(plain))
}

func reverse_vigenere(key []byte, ciphertext []byte) {
	plain := make([]byte, len(ciphertext))
	for i, b := range ciphertext {
		shift := key[i%len(key)] - capA
		pb := b - shift
		if pb < capA {
			pb += 26
		}
		plain[i] = pb
	}
	log.Printf("Plain text: %s\n", string(plain))
}
