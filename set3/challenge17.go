package set3

import (
	"crypto/rand"
	"cryptopals/set2"
	"cryptopals/xor"
	"encoding/base64"
	"log"
	"math/big"
)

var blocks = []string{
	"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
	"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
	"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
	"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
	"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
	"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
	"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
	"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
	"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
	"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
}

func getKey() []byte {
	key := make([]byte, 16)
	rand.Read(key)
	return key
}

func encryptRandomBlock_old(key []byte) ([]byte, string) {
	// source := mrnd.NewSource(time.Now().UnixNano())
	// r := mrnd.New(source)

	// index := r.Intn(len(blocks))
	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(len(blocks))))
	if err != nil {
		panic(err) // Should not happen in normal OS environments
	}
	index := int(nBig.Int64())
	// index := mrnd.Intn(len(blocks))
	// index = 9
	// estr := []byte(blocks[index])
	decoded, _ := base64.StdEncoding.DecodeString(blocks[index])
	padded := set2.PKCS7Padding(decoded, 16)
	cipher := set2.EncryptCBC_NP(key, padded, make([]byte, 16))
	return cipher, string(decoded)
}

func decryptOracle(key []byte, cipher []byte) bool {
	padded := set2.DecryptCBC(key, cipher, make([]byte, 16))
	_, err := set2.PKCS7UnpaddingErr(padded)
	if err != nil {
		return false
	}
	return true
}

func getBlock_old(key []byte, current []byte, prev []byte) []byte {
	// modifed prev to get current to return true
	var i int
	index := 15
	oprev := make([]byte, 16)
	ocurrent := make([]byte, 16)
	copy(ocurrent, current)
	copy(oprev, prev)
	intermediate_block := make([]byte, 16)
	for index = 15; index >= 0; index -= 1 {
		for i = 0; i < 256; i += 1 {
			prev[index] = byte(i)
			if decryptOracle(key, append(prev, ocurrent...)) {
				if index == 15 {
					// Flip the byte next to it to break accidental 0x02 0x02 padding
					prev[14] ^= 0x01
					valid := decryptOracle(key, append(prev, ocurrent...))
					prev[14] ^= 0x01
					if !valid {
						continue // It was a false positive, keep searching
					}
				}
				// we have a winner
				intermediate_block[index] = byte(16-index) ^ prev[index]
				// fix values for next round
				for j := index; j < 16; j += 1 {
					prev[j] = intermediate_block[j] ^ byte(16-(index-1))
				}
				break
			}
		}
	}
	plain_block := xor.XorBytes(intermediate_block, oprev)
	return plain_block
}

func c17_attack_old() (string, string) {
	key := getKey()
	cipher, answer := encryptRandomBlock(key)
	block_size := len(key)
	num_blocks := len(cipher) / block_size
	log.Printf("Decryptng %d blocks\n", num_blocks)
	results := make([]byte, 0)
	// one block at a time
	prev := make([]byte, 16)
	current := make([]byte, 16)
	for block := range num_blocks {
		if block == 0 {
			copy(prev, make([]byte, 16))
		} else {
			copy(prev, cipher[(block-1)*16:block*16])
		}
		copy(current, cipher[block*16:(block+1)*16])
		plain_block := getBlock(key, current, prev)
		log.Printf("Current block: %s\n", string(plain_block))
		results = append(results, plain_block...)
	}
	results, err := set2.PKCS7UnpaddingErr(results)
	if err != nil {
		log.Printf("Error unpadding result")
		// results = set2.PKCS7Unpadding(results)
	}
	return string(results), answer
}

// retry

func encryptRandomBlock(key []byte) ([]byte, string) {
	nBig, _ := rand.Int(rand.Reader, big.NewInt(int64(len(blocks))))
	index := int(nBig.Int64())

	// FIX: Decode the Base64 first!
	decoded, _ := base64.StdEncoding.DecodeString(blocks[index])

	padded := set2.PKCS7Padding(decoded, 16)
	// Using a Zero-IV for simplicity as per your current setup
	cipher := set2.EncryptCBC_NP(key, padded, make([]byte, 16))
	return cipher, blocks[index]
}

func getBlock(key []byte, current []byte, prev []byte) []byte {
	// Create a local working copy to avoid any side effects
	workingPrev := make([]byte, 16)
	copy(workingPrev, prev)

	intermediate_block := make([]byte, 16)

	for index := 15; index >= 0; index-- {
		padding_target := byte(16 - index)

		for i := 0; i < 256; i++ {
			workingPrev[index] = byte(i)

			// append is safe here as it will allocate a new backing array
			if decryptOracle(key, append(workingPrev, current...)) {
				// Special check for the last byte to avoid 0x02 0x02 false positives
				if index == 15 {
					workingPrev[14] ^= 0x01
					isStillValid := decryptOracle(key, append(workingPrev, current...))
					workingPrev[14] ^= 0x01 // ALWAYS restore the bit

					if !isStillValid {
						continue // It was a false positive, keep searching
					}
				}

				// Calculate intermediate byte
				intermediate_block[index] = workingPrev[index] ^ padding_target

				// Prepare the workingPrev for the next byte (index - 1)
				// We need all recovered bytes to result in (padding_target + 1)
				for j := index; j < 16; j++ {
					workingPrev[j] = intermediate_block[j] ^ (padding_target + 1)
				}
				break
			}
		}
	}

	// Final XOR with the ORIGINAL previous ciphertext block
	return xor.XorBytes(intermediate_block, prev)
}

func c17_attack() (string, string) {
	key := getKey()
	cipher, answerB64 := encryptRandomBlock(key)

	// Decode answer so we can compare the actual plaintext
	decodedAnswer, _ := base64.StdEncoding.DecodeString(answerB64)

	block_size := 16
	num_blocks := len(cipher) / block_size
	results := make([]byte, 0)

	for block := 0; block < num_blocks; block++ {
		var prev []byte
		if block == 0 {
			prev = make([]byte, 16)
		} else {
			prev = cipher[(block-1)*16 : block*16]
		}

		current := cipher[block*16 : (block+1)*16]
		plain_block := getBlock(key, current, prev)
		results = append(results, plain_block...)
	}

	// Finally, unpad the whole result
	unpadded, err := set2.PKCS7UnpaddingErr(results)
	if err != nil {
		log.Printf("Final unpadding failed: %v", err)
		return string(results), string(decodedAnswer)
	}

	return string(unpadded), string(decodedAnswer)
}
