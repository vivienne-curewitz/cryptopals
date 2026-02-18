package set2

import (
	"bytes"
	"fmt"
	"strings"
)

// Parse converts a k=v&k2=v2 string into a map
func Parse(input string) map[string]string {
	result := make(map[string]string)
	pairs := strings.Split(input, "&")
	for _, pair := range pairs {
		kv := strings.Split(pair, "=")
		if len(kv) == 2 {
			result[kv[0]] = kv[1]
		}
	}
	return result
}

// ProfileFor creates an encoded profile string, sanitizing input
func ProfileFor(email string) string {
	// Sanitize: strip & and =
	email = strings.ReplaceAll(email, "&", "")
	email = strings.ReplaceAll(email, "=", "")

	// In this scenario, UID is fixed at 10 and role is user
	return fmt.Sprintf("email=%s&uid=10&role=user", email)
}

func c13() {
	// author's faboirte key
	key := []byte("YELLOW SUBMARINE") // 16 bytes

	//admin + padding
	adminPadding := string(bytes.Repeat([]byte{byte(11)}, 11))
	email1 := "1234567890" + "admin" + adminPadding

	padded := PKCS7Padding([]byte(ProfileFor(email1)), 16)
	cipher1 := EncryptECB(key, padded)
	// get block with role data
	adminBlock := cipher1[16:32]

	// create profile to elevate privileges
	email2 := "abc@gmail.com" // 13 chars
	padded2 := PKCS7Padding([]byte(ProfileFor(email2)), 16)
	cipher2 := EncryptECB(key, padded2)

	// stitch together
	hackedCipher := append(cipher2[:32], adminBlock...)

	decrypted := DecryptECB(key, hackedCipher)
	fmt.Printf("Decrypted: %s\n", string(decrypted))

	parsed := Parse(string(decrypted))
	fmt.Printf("Parsed Role: %s\n", parsed["role"])
}
