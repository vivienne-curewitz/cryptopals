package xor

import (
	"encoding/hex"
	"log"
)

func XorBytes(b1 []byte, b2 []byte) []byte {
	output := make([]byte, len(b1))
	for i := range len(b1) {
		output[i] = b1[i] ^ b2[i]
	}
	return output
}

func xorHex(hexS1 string, hexS2 string) []byte {
	hexb1, err := hex.DecodeString(hexS1)
	if err != nil {
		log.Panicf("First string incorrect: %s\n", err)
	}
	hexb2, err := hex.DecodeString(hexS2)
	if err != nil {
		log.Panicf("Second string incorrect: %s\n", err)
	}
	if len(hexb1) != len(hexb2) {
		log.Panic("Input length unequal")
	}
	return XorBytes(hexb1, hexb2)
}
