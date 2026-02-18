package set2

import (
	"crypto/rand"
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
	cipherText := EncryptECB(key, plaintext)
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

func TestChallenge11(t *testing.T) {
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

func TestChallenge13(t *testing.T) {
	c13()
}

func TestChallenge14(t *testing.T) {
	c14_crack()
}

func TestChallenge15(t *testing.T) {
	correct := []byte("ICE ICE BABY\x04\x04\x04\x04")
	wrong1 := []byte("ICE ICE BABY\x05\x05\x05\x05")
	wrong2 := []byte("ICE ICE BABY\x01\x02\x03\x04")

	_, err := PKCS7UnpaddingErr(correct)
	assert.NoError(t, err)
	_, err = PKCS7UnpaddingErr(wrong1)
	assert.Error(t, err)
	_, err = PKCS7UnpaddingErr(wrong2)
	assert.Error(t, err)
}

func TestC16f1(t *testing.T) {
	input := "asdfasdfasdfas;=df"
	expected := "comment1=cooking%20MCs;userdata=" + "asdfasdfasdfasdf" + ";comment2=%20like%20a%20pound%20of%20bacon"
	assert.Equal(t, expected, f1(input))
}

func TestC16f2(t *testing.T) {
	input := "no_int;;=eresting_data"
	key := make([]byte, 16)
	rand.Read(key)
	cipher := f1Enc(input, key)
	f2Dec(cipher, key)
}

func TestChallenge16(t *testing.T) {
	key := make([]byte, 16)
	rand.Read(key)
	veryPreciseBitFlips(key)
}
