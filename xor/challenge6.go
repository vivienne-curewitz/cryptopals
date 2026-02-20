package xor

import (
	"log"
)

func countSetBits(b1 []byte) int {

	// instead of writing the slice manually
	// you can start with 0b00000001 and perform a left shift before every &
	// 0b00000001 << 1 == 0b00000010
	oneSetBitByteSlice := []byte{
		0b00000001,
		0b00000010,
		0b00000100,
		0b00001000,
		0b00010000,
		0b00100000,
		0b01000000,
		0b10000000,
	}

	hammingDist := 0

	for _, b := range b1 {
		for _, oneSetBitByte := range oneSetBitByteSlice {
			if (b & oneSetBitByte) > 0 {
				hammingDist += 1
			}
		}
	}

	return hammingDist
}

func editDistance(s1 string, s2 string) int {
	xb := XorBytes([]byte(s1), []byte(s2))
	return countSetBits(xb)
}

func editDistanceBytes(b1 []byte, b2 []byte) float64 {
	xb := XorBytes(b1, b2)
	return float64(countSetBits(xb))
}

// asume min ks = 2, max = 40;
// configuration would be nice but I have to do 24 of these lmao
func estimateKeySize(cipher []byte) int {
	min := 2
	max := 40
	bestScore := 1000000000000000000.0
	ks := 0
	for i := min; i <= max; i += 1 {
		score_sum := 0.0
		steps := 0.0
		for bi := range 5 {
			for bj := bi + 1; bj < 5; bj += 1 {
				steps += 1
				block1 := cipher[bi*i : i*(bi+1)]
				block2 := cipher[bj*i : i*(bj+1)]
				score_sum += editDistanceBytes(block1, block2) / float64(i)
			}
		}
		score := score_sum / steps
		if score < bestScore {
			bestScore = score
			ks = i
		}
	}
	return ks
}

func CipherTranspose(cipher []byte, keysize int) [][]byte {
	num_blocks := len(cipher) / keysize
	blocks := make([][]byte, num_blocks)
	for i := 0; i < len(cipher); i += keysize {
		if i+keysize <= len(cipher) {
			blocks[i/keysize] = cipher[i : i+keysize]
		} // } else { // I think I can get away with skipping the last block
		// 	blocks[i] = append(cipher[i:], make([]byte, i+keysize-len(cipher))...)
		// }
	}
	transpose := make([][]byte, keysize)
	for i := range keysize {
		transpose[i] = make([]byte, num_blocks)
		// copy(transpose[i], blocks[j][i])
		for j := range num_blocks {
			transpose[i][j] = blocks[j][i]
		}
	}
	return transpose
}

func SolveBlocks(transpose [][]byte) []byte {
	likelyKeys := make([]byte, len(transpose))
	for i, block := range transpose {
		key, _, _ := decryptXORInputBytes(block)
		likelyKeys[i] = key
	}
	return likelyKeys
}

func crackRepeatingKeyXOR(cipher []byte) {
	keysize := estimateKeySize(cipher)
	transpose := CipherTranspose(cipher, keysize)
	likelyKeys := SolveBlocks(transpose)
	log.Printf("Likely Key: %s\n", string(likelyKeys))
}
