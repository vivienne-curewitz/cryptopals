package main

import (
	"cryptopals/cryptanalysis"
	"os"
)

func main() {
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
