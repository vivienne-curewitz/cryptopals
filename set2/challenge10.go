package set2

import (
	"crypto/aes"
	"cryptopals/xor"
	"log"
)

// old encrypt function ECB
func EncryptECB(key []byte, plaintext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	// of course I picked the language where i have to do this manually
	encypted := make([]byte, len(plaintext))
	blockSize := block.BlockSize()

	for i := 0; i < len(plaintext); i += blockSize {
		block.Encrypt(encypted[i:i+blockSize], plaintext[i:i+blockSize])
	}
	return encypted
}

func DecryptECB(key []byte, cipher []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	// of course I picked the language where i have to do this manually
	decrypted := make([]byte, len(cipher))
	blockSize := block.BlockSize()

	for i := 0; i < len(cipher); i += blockSize {
		block.Decrypt(decrypted[i:i+blockSize], cipher[i:i+blockSize])
	}
	return decrypted
}

// new block encrypt
func EncryptCBC(key []byte, plaintext []byte, iv []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	num_blocks := len(plaintext) / len(key)
	if len(plaintext)%len(key) != 0 {
		num_blocks += 1
	}
	padded_size := num_blocks * len(key)
	plaintext = PadToLength(plaintext, padded_size)
	// of course I picked the language where i have to do this manually
	encypted := make([]byte, len(plaintext))
	blockSize := block.BlockSize()
	// first block with iv
	xor_enc := xor.XorBytes(iv, plaintext[0:blockSize])
	block.Encrypt(encypted[:blockSize], xor_enc)
	// rest of blocks
	for i := blockSize; i < len(plaintext); i += blockSize {
		xor_enc := xor.XorBytes(encypted[i-blockSize:i], plaintext[i:i+blockSize])
		block.Encrypt(encypted[i:i+blockSize], xor_enc)
	}
	return encypted
}

func DecryptCBC(key []byte, ciphertext []byte, iv []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	// of course I picked the language where i have to do this manually
	decrypted := make([]byte, len(ciphertext))
	blockSize := block.BlockSize()
	// first block with iv
	// rest of blocks
	dec_a := make([]byte, blockSize)
	for i := len(ciphertext) - blockSize; i >= 0; i -= blockSize {
		enc_a := ciphertext[i : i+blockSize]
		block.Decrypt(dec_a, enc_a)
		if i != 0 {
			dec_b := xor.XorBytes(ciphertext[i-blockSize:i], dec_a)
			copy(decrypted[i:], dec_b)
		} else {
			copy(decrypted[i:], dec_a)
		}
	}
	return decrypted
}

func EncryptCBC_NP(key []byte, plaintext []byte, iv []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	encypted := make([]byte, len(plaintext))
	blockSize := block.BlockSize()
	// first block with iv
	xor_enc := xor.XorBytes(iv, plaintext[0:blockSize])
	block.Encrypt(encypted[:blockSize], xor_enc)
	// rest of blocks
	for i := blockSize; i < len(plaintext); i += blockSize {
		xor_enc := xor.XorBytes(encypted[i-blockSize:i], plaintext[i:i+blockSize])
		block.Encrypt(encypted[i:i+blockSize], xor_enc)
	}
	return encypted
}
