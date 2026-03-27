package main

import (
	"cryptopals/cryptanalysis"
	"log"
	"os"
	"sync"
)

type result struct {
	Key   []byte
	Score float64
}

func subsitution_crack() {
	raw, _ := os.ReadFile("cryptanalysis/foundations_hw1.txt")
	cipher := cryptanalysis.Strip_text(raw)
	// key, plain := cryptanalysis.Guess_key(cipher, nil)
	key := parallel_substitutions(cipher)
	plain := cryptanalysis.Substitution_cypher(key, cipher)
	log.Printf("Key: %s\n", key)
	// plain := cryptanalysis.Substitution_cypher(key, cipher)
	log.Printf("Plain: %s\n", plain)
}

func subsitution_routine(cipher []byte, output chan result, wg *sync.WaitGroup) {
	key, score := cryptanalysis.Guess_key(cipher, nil)
	output <- result{
		Key:   []byte(key),
		Score: score,
	}
	wg.Done()
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

func parallel_substitutions(cipher []byte) []byte {
	wg := sync.WaitGroup{}
	iters := 100
	output := make(chan result, iters)
	for range iters {
		wg.Add(1)
		go subsitution_routine(cipher, output, &wg)
	}
	wg.Wait()
	best_result := result{}
	for range iters {
		r2 := <-output
		if r2.Score > best_result.Score {
			best_result = r2
		}
	}
	log.Printf("Best Score: %f\n", best_result.Score)
	return best_result.Key
}

func foundations_crack(raw []byte) {
	cipher := cryptanalysis.Strip_text(raw)
	// for i := 3; i <= 10; i += 1 {
	vigenere_key := cryptanalysis.Vigenere_crack(cipher)
	// vigenere_key := cryptanalysis.Vigenere_Relative(cipher, 14)
	vig_cipher := cryptanalysis.Reverse_vigenere(vigenere_key, cipher)
	sub_key := parallel_substitutions(vig_cipher)
	sub_text := cryptanalysis.Substitution_cypher(sub_key, vig_cipher)
	log.Printf("Sub Key: %s\n", sub_key)
	log.Printf("Plain?: %s\n", sub_text)
	// }
}

func test_sub_vig_crack() {
	cipher, _ := os.ReadFile("cryptanalysis/rcypher1.txt")
	key := []byte("SKILL")
	vc := cryptanalysis.Encrypt_Vigenere(key, cipher)
	foundations_crack(vc)
}

func main() {
	subsitution_crack()
	// raw, _ := os.ReadFile("cryptanalysis/foundations_hw1.txt")
	// foundations_crack(raw)
	// test_sub_vig_crack()
}
