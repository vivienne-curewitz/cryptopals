package set2

// import "crypto/rand"

import (
	rnd "crypto/rand"
	"math/rand"
)

const (
	CBC = iota
	ECB
)

func RandomEncrypt(plaintext []byte) ([]byte, int) {
	prepend := rand.Intn(5) + 5
	append := rand.Intn(5) + 5
	to_encrypt := make([]byte, len(plaintext)+prepend+append)
	for i := range len(to_encrypt) {
		to_encrypt[i] = 0x4
	}
	copy(to_encrypt[prepend:], plaintext)
	key := make([]byte, 16)
	rnd.Read(key)
	if rand.Intn(1000) < 500 {
		// ECB
		// pad to length
		delta := 16 - (len(to_encrypt) % 16)
		to_encrypt = PadToLength(to_encrypt, len(to_encrypt)+delta)
		return EncryptCB(key, to_encrypt), ECB
	} else {
		return EncryptCBC(key, to_encrypt, make([]byte, 16)), CBC
	}
}

func DetectECB_CBC(ciphertext []byte, blocksize int) int {
	for i := 0; i < len(ciphertext)-(2*blocksize); i += 1 {
		if string(ciphertext[i:i+blocksize]) == string(ciphertext[i+blocksize:i+(2*blocksize)]) {
			return ECB
		}
	}
	return CBC
}
