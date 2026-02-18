package set2

import (
	"crypto/rand"
	"encoding/base64"
	"log"
	"slices"
)

func c12_init() ([]byte, []byte) {
	base64txt := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	decoded, _ := base64.StdEncoding.DecodeString(base64txt)
	// now append decoded to a plaintext?
	// random encryption key
	key := make([]byte, 16)
	rand.Read(key)
	return key, decoded
}

func c12_encrypt(key []byte, unk []byte, input []byte) []byte {
	to_encrypt := append(input, unk...)
	delta := 16 - len(to_encrypt)%16
	to_encrypt = PadToLength(to_encrypt, delta+len(to_encrypt))
	return EncryptECB(key, to_encrypt)
}

func c12_crack() {
	key, decoded := c12_init()
	text := []byte{'A'}
	first_block_size := len(c12_encrypt(key, decoded, text))
	next_block_size := first_block_size
	for next_block_size == first_block_size {
		text = append(text, 'A')
		next_block_size = len(c12_encrypt(key, decoded, text))
	}
	block_size := next_block_size - first_block_size
	log.Printf("Block Size: %d\n", block_size)

	var j byte
	decrypted := make([]byte, len(decoded))
	for di := range len(decoded) {
		// generate encryption
		// generate bytes equal to block size - 1
		spoof_text := make([]byte, block_size-1)
		for i := range len(spoof_text) {
			spoof_text[i] = 'A'
		}
		cipher := c12_encrypt(key, decoded[di:], spoof_text)
		// compare first byte to all possible inputs
		block1 := cipher[:block_size]
		spoof_text = append(spoof_text, 0)
		for j = range 255 {
			spoof_text[block_size-1] = j
			block2 := c12_encrypt(key, decoded[di:], spoof_text)
			if slices.Compare(block1, block2[:block_size]) == 0 {
				// we have a winner
				// log.Printf("Found %d byte: %b\n", di, spoof_text[block_size-1])
				decrypted[di] = spoof_text[block_size-1]
				// copy(spoof_text[:block_size-1], spoof_text[1:block_size])
				break
			}
		}
	}
	log.Printf("Decrypted:\n%s\n", string(decrypted))

}
