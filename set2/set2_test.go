package set2

import (
	"cryptopals/xor"
	"encoding/base64"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPadToLength(t *testing.T) {
	input := []byte("YELLOW SUBMARINE")
	output := PadToLength(input, 20)
	expected := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")
	assert.Equal(t, expected, output)
}

func TestEncrypt(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	plaintext := []byte("Silly goose two2")
	cipherText := EncryptCB(key, plaintext)
	pt2 := xor.DecryptAESECBBytes(key, cipherText)
	assert.Equal(t, plaintext, pt2)
}

func TestCBCEncrypt(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	iv := make([]byte, 16) // 16 0's
	plaintext := []byte("Silly goose two2")
	cipherText := EncryptCBC(key, plaintext, iv)
	pt2 := DecryptCBC(key, cipherText, iv)
	assert.Equal(t, plaintext, pt2)
	log.Printf("Decrypted: %s\n", pt2)
}

func TestCBCChallenge10(t *testing.T) {
	filename := "c10.txt"
	rawContent, err := os.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}

	// 1. Remove newlines/whitespace so the Base64 decoder doesn't trip
	inputString := strings.ReplaceAll(string(rawContent), "\n", "")
	inputString = strings.ReplaceAll(inputString, "\r", "")

	// 2. Convert Base64 text to actual ciphertext bytes
	ciphertext, err := base64.StdEncoding.DecodeString(inputString)
	if err != nil {
		log.Fatal("Base64 decode error:", err)
	}

	key := []byte("YELLOW SUBMARINE")
	iv := make([]byte, 16) // 16 0's
	data := DecryptCBC(key, ciphertext, iv)
	log.Printf("Decrypted: %s\n", data)
}

func TestChallenge3(t *testing.T) {
	plaintext := []byte("Silly goose two2Silly goose two2Silly goose two2")
	for range 10 {
		ciphertext, ans := RandomEncrypt(plaintext)
		detected := DetectECB_CBC(ciphertext, 16)
		assert.Equal(t, ans, detected)
	}
}

func TestChallenge12(t *testing.T) {
	c12_crack()
}
