package set3

import (
	"crypto/aes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
)

// encrypt and decrypt??
func CTR(key []byte, nonce uint64, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	size := block.BlockSize() // Should be 16 for AES
	out := make([]byte, len(data))

	for i := 0; i < len(data); i += size {
		// counter here
		counterBlock := make([]byte, size)
		binary.LittleEndian.PutUint64(counterBlock[:8], nonce)
		binary.LittleEndian.PutUint64(counterBlock[8:], uint64(i/size))

		keystream := make([]byte, size)
		block.Encrypt(keystream, counterBlock)

		for j := 0; j < size && i+j < len(data); j++ {
			out[i+j] = data[i+j] ^ keystream[j]
		}
	}

	return out, nil
}

func c18() {
	key := []byte("YELLOW SUBMARINE")
	b64Input := "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="

	ciphertext, _ := base64.StdEncoding.DecodeString(b64Input)

	plaintext, err := CTR(key, 0, ciphertext)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Decrypted: %s\n", string(plaintext))
}
