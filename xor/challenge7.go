package xor

import (
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"
)

func DecryptAESECB(key []byte, filename string) {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	enc := base64.NewDecoder(base64.StdEncoding, file)
	ciphertext, err := io.ReadAll(enc)

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	// of course I picked the language where i have to do this manually
	decrypted := make([]byte, len(ciphertext))
	blockSize := block.BlockSize()

	for i := 0; i < len(ciphertext); i += blockSize {
		block.Decrypt(decrypted[i:i+blockSize], ciphertext[i:i+blockSize])
	}

	fmt.Printf("%s\n", decrypted)
}

func DecryptAESECBBytes(key []byte, ciphertext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	// of course I picked the language where i have to do this manually
	decrypted := make([]byte, len(ciphertext))
	blockSize := block.BlockSize()

	for i := 0; i < len(ciphertext); i += blockSize {
		block.Decrypt(decrypted[i:i+blockSize], ciphertext[i:i+blockSize])
	}

	fmt.Printf("%s\n", decrypted)
	return decrypted
}
