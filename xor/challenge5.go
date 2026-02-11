package xor

import "encoding/hex"

func repeatingXOR(hexIn string, key string) string {
	// hexb, err := hex.DecodeString(hexIn)
	// if err != nil {
	// 	log.Panicf("oof: %s\n", err)
	// }
	hexb := hexIn
	cipher := make([]byte, len(hexb))
	for i := range hexb {
		cipher[i] = hexb[i] ^ key[i%len(key)]
	}
	return hex.EncodeToString(cipher)
}
