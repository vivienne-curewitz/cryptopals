package main

import (
	"cryptopals/cryptanalysis"
	"log"
	"os"
)

func subsitution_crack() {
	cipher, _ := os.ReadFile("cryptanalysis/rcypher2.txt")
	// prev_key, _ := os.ReadFile("ncypher23_found.key")
	// rkey, _ := os.ReadFile("cryptanalysis/ncypher2.key")
	key, _ := os.ReadFile("rcypher_1000000_found_human.key")
	// key, text := cryptanalysis.Guess_key(cipher, nil)
	// log.Printf("Got Key:\n%s\nExpected:\n%s\n", string(key), string(rkey))
	// os.WriteFile("rcypher_1000000_found.key", []byte(key), 0666)
	// os.WriteFile("rcypher2_plaintext.txt", []byte(text), 0666)
	plain := cryptanalysis.Substitution_cypher(key, cipher)
	os.WriteFile("plain_text_twiddle.txt", plain, 0666)
	// set3.CrackRandSeed()
}

func vigenere_crack() {
	cipher, _ := os.ReadFile("cryptanalysis/rcypher1.txt")
	key_len := cryptanalysis.Kasiski_search(cipher)
	log.Printf("Key Length: %d\n", key_len)
	key := cryptanalysis.Vigenere_key_search(cipher, 5)
	log.Printf("Key: %s\n", string(key))
	key2, plain := cryptanalysis.Guess_key_vignere(cipher, key)
	log.Printf("Key1: %s\nKey2: %s\nPlain: %s\n", string(key), key2, plain)
}

func main() {
	// vigenere_crack()
	cipher, _ := os.ReadFile("cryptanalysis/rcypher1.txt")
	plain := cryptanalysis.Reverse_vigenere([]byte("SKILL"), cipher)
	log.Printf("Plain: %s\n", string(plain))
}
