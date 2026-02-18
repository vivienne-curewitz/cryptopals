package set2

import (
	"log"
	"strings"
)

// Parse converts a k=v&k2=v2 string into a map
func Parse2(input string) map[string]string {
	result := make(map[string]string)
	pairs := strings.Split(input, ";")
	for _, pair := range pairs {
		kv := strings.Split(pair, "=")
		if len(kv) == 2 {
			result[kv[0]] = kv[1]
		}
	}
	return result
}

func f1(input string) string {
	pre := "comment1=cooking%20MCs;userdata="
	post := ";comment2=%20like%20a%20pound%20of%20bacon"
	input = strings.ReplaceAll(input, ";", "")
	input = strings.ReplaceAll(input, "=", "")
	return pre + input + post
}

func f1Enc(input string, key []byte) []byte {
	plaintext := []byte(f1(input))
	to_encrypt := PKCS7Padding(plaintext, len(key))
	return EncryptCBC(key, to_encrypt, make([]byte, len(key)))
}

func f2Dec(cipherText []byte, key []byte) bool {
	iv := make([]byte, len(key))
	plaintext := DecryptCBC(key, cipherText, iv)
	log.Printf("%s\n", plaintext)
	results := Parse2(string(plaintext))
	_, exists := results["admin"]
	if exists {
		return true
	}
	return false
}

func veryPreciseBitFlips(key []byte) {
	input := ":admin<true:AAAA"
	ciphertext := f1Enc(input, key)

	// modify block before admin block (that block will get cooked)
	// but admin block will just have the single bit flip
	// replacements ; = : and < = =
	ciphertext[16] ^= (':' ^ ';') // first byte in block before admin - this overflows to admin block

	// 16 + 6 is < index
	ciphertext[22] ^= ('<' ^ '=') //block before admin block
	// 16 + 11 is : index
	ciphertext[27] ^= (':' ^ ';') //block before admin block

	// 3. Test it
	isAdmin := f2Dec(ciphertext, key)
	log.Printf("Is Admin: %v\n", isAdmin)
}
