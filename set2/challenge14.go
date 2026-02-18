package set2

import (
	"crypto/rand"
	"encoding/base64"
	"log"
	mrnd "math/rand"
	"slices"
	"time"
)

// key, decoded, random_text
func c14_init() ([]byte, []byte, []byte) {
	base64txt := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	decoded, _ := base64.StdEncoding.DecodeString(base64txt)
	// now append decoded to a plaintext?
	// random encryption key
	key := make([]byte, 16)
	rand.Read(key)
	mrnd.Seed(time.Now().Unix())
	text_size := mrnd.Intn(64)
	random_text := make([]byte, text_size)
	log.Printf("Random Text size: %d\n", len(random_text))
	rand.Read(random_text)
	return key, decoded, random_text
}

func c14_encrypt(key []byte, unk []byte, input []byte, random_text []byte) []byte {
	to_encrypt := append(input, unk...)
	to_encrypt = append(random_text, to_encrypt...)
	to_encrypt = PKCS7Padding(to_encrypt, len(key))
	return EncryptECB(key, to_encrypt)
}

func c14_crack() {
	key, decoded, random_text := c14_init()
	text := []byte{'A'}
	first_block_size := len(c14_encrypt(key, decoded, text, random_text))
	next_block_size := first_block_size
	for next_block_size == first_block_size {
		text = append(text, 'A')
		next_block_size = len(c14_encrypt(key, decoded, text, random_text))
	}
	block_size := next_block_size - first_block_size
	log.Printf("Block Size: %d\n", block_size)

	// before searching for decrypted, need to find the end of random text
	oracle_text := make([]byte, 2*block_size)
	for i := range len(oracle_text) {
		oracle_text[i] = 'A'
	}
	enc_block := EncryptECB(key, oracle_text[:block_size])
	start_width := len(oracle_text)
	oracle_index := 0
	for {
		cipher := c14_encrypt(key, decoded, oracle_text[:start_width], random_text)
		found := false
		for i := range len(cipher) - block_size {
			if slices.Compare(enc_block, cipher[i:i+block_size]) == 0 {
				oracle_index = i
				start_width -= 1
				found = true
				break
			}
		}
		if !found {
			break
		}
	}
	log.Printf("Oracle start Index: %d -- width: %d\n", oracle_index, start_width)
	block_end := oracle_index + block_size

	var j byte
	decrypted := make([]byte, len(decoded))
	for di := range len(decoded) {
		// generate encryption
		// generate bytes equal to block size - 1
		spoof_text := make([]byte, start_width)
		for i := range len(spoof_text) {
			spoof_text[i] = 'A'
		}
		cipher := c14_encrypt(key, decoded[di:], spoof_text, random_text)
		// compare first byte to all possible inputs
		block1 := cipher[oracle_index:block_end]
		spoof_text = append(spoof_text, 0)
		for j = range 255 {
			spoof_text[start_width] = j
			block2 := c14_encrypt(key, decoded[di:], spoof_text, random_text)
			if slices.Compare(block1, block2[oracle_index:block_end]) == 0 {
				// we have a winner
				// log.Printf("Found %d byte: %b\n", di, spoof_text[block_size-1])
				decrypted[di] = spoof_text[start_width]
				// copy(spoof_text[:block_size-1], spoof_text[1:block_size])
				break
			}
		}
	}
	log.Printf("Decrypted:\n%s\n", string(decrypted))

}
