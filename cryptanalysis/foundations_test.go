package cryptanalysis

import (
	"log"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFreqGen(t *testing.T) {
	val := normalize_freq_data(true)
	log.Printf("%v\n", val)
	var sum float64 = 0
	for _, f := range val {
		sum += f
	}
	log.Printf("Normalize total Freq: %f\n", sum)
}

func TestEncDecV(t *testing.T) {
	key := []byte("SKILL")
	cipher, _ := os.ReadFile("rcypher1.txt")
	plain := Reverse_vigenere(key, cipher)
	c2 := Encrypt_Vigenere(key, plain)
	assert.Equal(t, cipher, c2)
}

func TestFindSubstitutionKEy(t *testing.T) {
	raw, _ := os.ReadFile("foundations_hw1.txt")
	cipher := Strip_text(raw)
	key := generate_substitution_key(cipher)
	log.Printf("Key: %s\n", key)
	plain := Substitution_cypher(key, cipher)
	log.Printf("Plain: %s\n", plain)
}

func TestVigenereKnown(t *testing.T) {
	raw, _ := os.ReadFile("rcypher1.txt")
	cipher := Strip_text(raw)
	key := Vigenere_crack(cipher, 0)
	plain := Reverse_vigenere(key, cipher)
	log.Printf("key: %s\nPlain: %s\n", key, plain)
}

func TestSubstitutionKnown(t *testing.T) {
	raw, _ := os.ReadFile("rcypher1.txt")
	cipher := Strip_text(raw)
	key := Substitution_hill_climb(10000, cipher)
	plain := Substitution_cypher(key, cipher)
	log.Printf("Plain: %s\n", plain)
}

func TestCeaserSearch(t *testing.T) {
	raw, _ := os.ReadFile("foundations_hw1.txt")
	cipher := Strip_text(raw)
	fm := normalize_freq_data(true)
	b := Ceaser_search(cipher, fm)
	plain := Ceaser_shift(cipher, b)
	log.Printf("byte: %b -- plain: %s\n", b, plain)
}

func TestVigenereCrackF(t *testing.T) {
	raw, _ := os.ReadFile("foundations_hw1.txt")
	cipher := Strip_text(raw)
	key := Vigenere_crack(cipher, 0)
	plain := Reverse_vigenere(key, cipher)
	log.Printf("key: %s\nPlain: %s\n", key, plain)
}

func TestVigenereThenSubstitution(t *testing.T) {
	raw, _ := os.ReadFile("foundations_hw1.txt")
	cipher := Strip_text(raw)
	key := Vigenere_crack(cipher, 0)
	cipher_2 := Reverse_vigenere(key, cipher)
	key2 := generate_substitution_key(cipher_2)
	log.Printf("Key: %s\n", key2)
	plain := Substitution_cypher(key2, cipher)
	log.Printf("Plain: %s\n", plain)
}

func TestSubstitutionThenVigenere(t *testing.T) {
	raw, _ := os.ReadFile("foundations_hw1.txt")
	cipher := Strip_text(raw)
	key2 := generate_substitution_key(cipher)
	log.Printf("Key: %s\n", key2)
	cipher_2 := Substitution_cypher(key2, cipher)
	key := Vigenere_crack(cipher, 0)
	plain := Reverse_vigenere(key, cipher_2)

	log.Printf("Plain: %s\n", plain)
}

func TestDivide(t *testing.T) {
	log.Printf("%d\n", 5/7)
}
