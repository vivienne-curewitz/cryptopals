package set3

import (
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestC17(t *testing.T) {
	log.Println("Running c17 test")
	results, answer := c17_attack()
	assert.Equal(t, answer, results)
}

func TestC18(t *testing.T) {
	c18()
}

func TestC19(t *testing.T) {
	c19()
}

func TestC20(t *testing.T) {
	c20()
}

func TestC21(t *testing.T) {
	const seed uint32 = 1234785678
	mtr := NewMTRand()
	mtr.initialize_state(seed)
	a := mtr.rand_int()
	b := mtr.rand_int()
	assert.NotEqual(t, a, b)
	mtr.initialize_state(seed)
	output := make([]uint32, 10)
	for i := range len(output) {
		output[i] = mtr.rand_int()
	}
	mtr.initialize_state(seed)
	for i := range len(output) {
		assert.Equal(t, output[i], mtr.rand_int())
	}
}

func TestC22(t *testing.T) {
	CrackRandSeed()
}

func TestReverseXor(t *testing.T) {
	x := uint32(1234123412)
	y := x ^ (x >> _u)
	x2 := undoRightShiftXor(y, _u)
	assert.Equal(t, x, x2)
}

func TestReverseXorMask(t *testing.T) {
	x := uint32(123412341)
	y := x ^ ((x << _s) & _b)
	x2 := undoLeftShiftXorMask(y, _s, _b)
	assert.Equal(t, x, x2)
}

func TestC23(t *testing.T) {
	_, clone, base := CloneMTR()
	test10 := make([]uint32, 10)
	for range len(test10) {
		assert.Equal(t, base.rand_int(), clone.rand_int())
	}
}

func TestKeyStreamEncDec(t *testing.T) {
	plaintext := []byte("IHateMondays")
	mtr := NewMTRand()
	seed := uint32(1234)
	cipher, key := encryptKeyStream(mtr, plaintext, seed)
	plain2 := decryptKeyStream(cipher, key)
	assert.Equal(t, plain2, plaintext)
}

func TestC24Part1(t *testing.T) {
	getKeyStream()
}

func TestC24Part2(t *testing.T) {
	checkIfKeystreamFromTimeSeed(5)
}
