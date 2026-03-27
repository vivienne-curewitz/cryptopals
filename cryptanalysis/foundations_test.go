package cryptanalysis

import (
	"log"
	"os"
	"testing"
)

func TestFreqGen(t *testing.T) {
	val := normalize_freq_data()
	log.Printf("%v\n", val)
	var sum float64 = 0
	for _, f := range val {
		sum += f
	}
	log.Printf("Normalize total Freq: %f\n", sum)
}

func TestFindSubstitutionKEy(t *testing.T) {
	raw, _ := os.ReadFile("foundations_hw1.txt")
	cipher := strip_text(raw)
	key := generate_substitution_key(cipher)
	log.Printf("Key: %s\n", key)
	plain := Substitution_cypher(key, cipher)
	log.Printf("Plain: %s\n", plain)
}

func TestCeaserSearch(t *testing.T) {
	raw, _ := os.ReadFile("foundations_hw1.txt")
	cipher := strip_text(raw)
	b := ceaser_search(cipher)
	plain := ceaser_shift(cipher, b)
	log.Printf("byte: %b -- plain: %s\n", b, plain)
}

func TestVigenereCrackF(t *testing.T) {
	raw, _ := os.ReadFile("foundations_hw1.txt")
	cipher := strip_text(raw)
	key := vigenere_crack(cipher)
	plain := Reverse_vigenere(key, cipher)
	log.Printf("key: %s\nPlain: %s\n", key, plain)
}

func TestDivide(t *testing.T) {
	log.Printf("%d\n", 5/7)
}
