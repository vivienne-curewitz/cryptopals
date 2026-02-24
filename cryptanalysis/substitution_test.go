package cryptanalysis

import (
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
	reverse_vigenere(key, cipher)
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
