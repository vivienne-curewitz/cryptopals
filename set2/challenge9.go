package set2

import (
	"bytes"
	"errors"
	"log"
)

func PadToLength(input []byte, length int) []byte {
	if length < len(input) {
		log.Panicf("Padded length is less than original length")
	}
	pad_byte := 0x04
	retval := make([]byte, length)
	for i := range retval {
		if i >= len(input) {
			retval[i] = byte(pad_byte)
		} else {
			retval[i] = input[i]
		}
	}
	return retval
}

// better padding functions
func PKCS7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func PKCS7Unpadding(data []byte) []byte {
	length := len(data)
	unpadding := int(data[length-1])
	return data[:(length - unpadding)]
}

// with error -- this is for challenge 15
func PKCS7UnpaddingErr(data []byte) ([]byte, error) {
	length := len(data)
	unpadding := int(data[length-1])
	if unpadding > length {
		return nil, errors.New("Incorrect Padding")
	}
	for i := (length - unpadding); i < length; i += 1 {
		if int(data[i]) != unpadding {
			return nil, errors.New("Incorrect Padding")
		}
	}
	return data[:(length - unpadding)], nil
}
