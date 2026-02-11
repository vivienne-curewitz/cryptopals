package xor

import (
	"bufio"
	"encoding/hex"
	"log"
	"os"
	"slices"
)

func detectRepeatingBlocks(data []byte) int {
	if len(data)%16 != 0 {
		log.Panic("Data size is not multiple of 16")
	}
	matches := 0
	for i := 0; i < len(data); i += 16 {
		for j := i + 16; j < len(data); j += 16 {
			if slices.Compare(data[i:i+16], data[j:j+16]) == 0 {
				matches += 1
			}
		}
	}
	return matches
}

func FindAESECBString(filename string) {
	file, _ := os.Open(filename)
	sc := bufio.NewScanner(file)
	mostMatches := 0
	aesLine := 0
	i := 0
	var aesBytes []byte
	for sc.Scan() {
		line := sc.Text()
		hb, err := hex.DecodeString(line)
		if err != nil {
			log.Panicf("Error decoding file line: %d %s\n", i, err)
		}
		matches := detectRepeatingBlocks(hb)
		if matches > mostMatches {
			mostMatches = matches
			aesLine = i
			aesBytes = hb
		}
		i += 1
	}
	log.Printf("AES Line: %d\n", aesLine)
	key := []byte("YELLOW SUBMARINE")
	DecryptAESECBBytes(key, aesBytes)
}
