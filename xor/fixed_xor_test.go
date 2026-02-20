package xor

import (
	"encoding/base64"
	"encoding/hex"
	"io"
	"log"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBase64Encode(t *testing.T) {
	input, _ := hex.DecodeString("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	dst := make([]byte, 4*len(input)/3)
	EncodeB64(dst, input)
	expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	output := string(dst)
	assert.Equal(t, expected, output)
}

// challenge 2
func TestFixedXor(t *testing.T) {
	s1 := "1c0111001f010100061a024b53535009181c"
	s2 := "686974207468652062756c6c277320657965"
	output := xorHex(s1, s2)
	expectedStr := "746865206b696420646f6e277420706c6179"
	expected, _ := hex.DecodeString(expectedStr)
	assert.Equal(t, output, expected)
}

// challenge 3
func TestDecrypt(t *testing.T) {
	inStr := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	key, _, text := decryptXORInput(inStr)
	log.Printf("Key: %d\nText: %s\n", key, text)

	// with byte function
	hb, _ := hex.DecodeString(inStr)
	k2, _, t2 := decryptXORInputBytes(hb)
	log.Printf("Key: %d\nText: %s\n", k2, t2)
}

// hcallenge 4
func TestDetect(t *testing.T) {
	ReadAndDetect("c4.txt")
}

// challenge 5
func TestRepeatingXOR(t *testing.T) {
	inStr := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	key := "ICE"
	expected := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	cipher := repeatingXOR(inStr, key)
	assert.Equal(t, cipher, expected)
}

func TestEditDistance(t *testing.T) {
	s1 := "this is a test"
	s2 := "wokka wokka!!!"
	ed := editDistance(s1, s2)
	assert.Equal(t, 37, ed)
}

func TestDivideInt(t *testing.T) {
	x := 5
	y := 4
	z := 7
	log.Printf("5/4 = %d\n", x/y)
	log.Printf("7/4 = %d\n", z/y)
}

// challenge 6
func TestCrackKey(t *testing.T) {
	file, err := os.Open("c6.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	enc := base64.NewDecoder(base64.StdEncoding, file)
	decoded, err := io.ReadAll(enc)
	if err != nil {
		log.Panicf("could not decode file: %s\n", err)
	}
	cipher := decoded
	crackRepeatingKeyXOR(cipher)
}

// challenge 7
func TestAESDecrypt(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	DecryptAESECB(key, "c7.txt")
}

// challenge 8
func TestFindAESLine(t *testing.T) {
	FindAESECBString("c8.txt")
}
