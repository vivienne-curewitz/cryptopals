package set3

import (
	crand "crypto/rand"
	"cryptopals/xor"
	"log"
	"math"
	"math/rand/v2"
	"slices"
	"time"
)

func encryptKeyStream(mtr *MTRand, plaintext []byte, seed uint32) ([]byte, []byte) {
	mtr.initialize_state(seed)
	keyStream := mtr.getKeyStream(len(plaintext))
	encrypted := xor.XorBytes(plaintext, keyStream)
	return encrypted, keyStream
}

func decryptKeyStream(cipher []byte, key []byte) []byte {
	return xor.XorBytes(cipher, key)
}

func getKeyStream() {
	num_pad := rand.IntN(10)
	plaintext := []byte("AAAAAAAAAAAAAAAAAAAA") // 20
	padding := make([]byte, num_pad)
	crand.Read(padding)
	to_encrypt := append(padding, plaintext...)
	mtr := NewMTRand()
	cipher, _ := encryptKeyStream(mtr, to_encrypt, 2345)
	tr := make([]byte, len(to_encrypt))
	for i := range tr {
		tr[i] = byte('A')
	}
	keyStream := xor.XorBytes(cipher, tr)

	// brute force here
	for i := range int(math.Pow(2, 16)) {
		mtr.initialize_state(uint32(i))
		ks := mtr.getKeyStream(len(keyStream))
		hits := 0
		for j, b := range ks {
			if b == keyStream[j] {
				hits += 1
			}
		}
		if hits > 10 {
			log.Printf("found seed: %d\n", i)
			break
		}
	}
}

func checkIfKeystreamFromTimeSeed(maxD int) {
	seed := time.Now().Unix()
	mtr := NewMTRand()
	mtr.initialize_state(uint32(seed))
	keyStream := mtr.getKeyStream(20) //just hardcode 20 for now
	crack_time := time.Now().Unix()
	start := crack_time - int64(maxD)
	var si uint32
	// clock drif
	tmtr := NewMTRand()
	for si = uint32(start); si < uint32(crack_time)+2; si += 1 {
		tmtr.initialize_state(si)
		ks := tmtr.getKeyStream(20)
		if slices.Compare(keyStream, ks) == 0 {
			log.Printf("Found Time Seed: %d -- %s\n", si, time.Unix(int64(si), 0))
		}
	}
}
