package cryptanalysis

import (
	"os"
	"testing"
)

func TestSubstitution(t *testing.T) {
	key, _ := os.ReadFile("ncypher2.key")
	cipher, _ := os.ReadFile("ncypher2.txt")
	substitution_cypher(key, cipher)
}

func TestPolySub(t *testing.T) {
	key, _ := os.ReadFile("ncypher2.key")
	cipher, _ := os.ReadFile("ncypher1.txt")
	seed := uint64(198431)
	polymorphic_substitution(key, cipher, seed)
}

func TestVigenere(t *testing.T) {
	key, _ := os.ReadFile("ncypher1.key")
	cipher, _ := os.ReadFile("ncypher1.txt")
	reverse_vigenere(key, cipher)
}
