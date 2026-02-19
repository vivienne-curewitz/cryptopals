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
