package set2

import "log"

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
