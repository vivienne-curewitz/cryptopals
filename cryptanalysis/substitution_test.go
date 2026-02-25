package cryptanalysis

import (
	"log"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSubstitution(t *testing.T) {
	key, _ := os.ReadFile("ncypher2.key")
	cipher, _ := os.ReadFile("ncypher2.txt")
	Substitution_cypher(key, cipher)
}

func TestVigenere(t *testing.T) {
	key, _ := os.ReadFile("ncypher1.key")
	cipher, _ := os.ReadFile("ncypher1.txt")
	Reverse_vigenere(key, cipher)
}

func TestFreqMap(t *testing.T) {
	cipher, _ := os.ReadFile("ncypher1.txt")
	generateLetterFrequencies(cipher)
}

func TestGuess_Key(t *testing.T) {
	cipher, _ := os.ReadFile("ncypher2.txt")
	rkey, _ := os.ReadFile("ncypher2.key")
	key, _ := Guess_key(cipher, nil)
	assert.Equal(t, rkey, key)
}

func TestKasisnskiSearc(t *testing.T) {
	cipher, _ := os.ReadFile("ncypher1.txt")
	key_len := Kasiski_search(cipher)
	log.Printf("Key Length: %d\n", key_len)
}

func TestVigenereCrack(t *testing.T) {
	cipher, _ := os.ReadFile("ncypher1.txt")
	key_len := Kasiski_search(cipher)
	log.Printf("Key Length: %d\n", key_len)
	key := Vigenere_key_search(cipher, key_len)
	log.Printf("Key: %s\n", string(key))
}

func TestVigenereCrack1(t *testing.T) {
	cipher, _ := os.ReadFile("rcypher1.txt")
	key_len := Kasiski_search(cipher)
	log.Printf("Key Length: %d\n", key_len)
	key := Vigenere_key_search(cipher, key_len)
	log.Printf("Key: %s\n", string(key))
}
