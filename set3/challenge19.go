package set3

import (
	"cryptopals/xor"
	"encoding/base64"
	"log"
	"strings"
	"unicode"
)

const input = `SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==
Q29taW5nIHdpdGggdml2aWQgZmFjZXM=
RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==
RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=
SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk
T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=
UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=
T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl
VG8gcGxlYXNlIGEgY29tcGFuaW9u
QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==
QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=
QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==
QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=
QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==
SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==
SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==
VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==
V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==
V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==
U2hlIHJvZGUgdG8gaGFycmllcnM/
VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=
QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=
VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=
V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=
SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==
U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==
U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=
VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==
QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu
SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=
VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs
WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=
SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0
SW4gdGhlIGNhc3VhbCBjb21lZHk7
SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=
VHJhbnNmb3JtZWQgdXR0ZXJseTo=
QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=`

func generateMany(key []byte, inputd string) [][]byte {
	data_in := strings.Split(inputd, "\n")
	output := make([][]byte, len(data_in))
	// if len(data_in) != 40 {
	// 	log.Panicf("Split failed lenght is %d\n", len(data_in))
	// }
	for i, line := range data_in {
		plaintext, _ := base64.StdEncoding.DecodeString(line)
		output[i], _ = CTR(key, 0, plaintext) //ignore error
	}
	return output
}

func scoreText(data []byte) float64 {
	// list generated with gippity
	frequencies := map[byte]float64{
		'e': .12702, 't': .09056, 'a': .08167, 'o': .07507, 'i': .06966,
		'n': .06749, 's': .06327, 'h': .06094, 'r': .05987, 'd': .04253,
		'l': .04025, 'u': .02758, ' ': .15000, // Spaces are very common
	}

	var score float64
	for _, b := range data {
		if (b < 32 || b > 126) && b != '\n' && b != '\r' && b != '\t' {
			score -= 10
			continue
		}

		lower := byte(unicode.ToLower(rune(b))) // ok, guess I can do normal
		score += frequencies[lower]
	}
	return score
}

// basically the same as challenge 3
func solveSingleByteXOR(column []byte) byte {
	var bestKey byte
	var highScore float64 = -1000000

	// try a byte against every value in the colum
	// this is the transpose of the original texts
	// so this is a column where all values are from the same point in the text
	for key := 0; key < 256; key++ {
		decrypted := make([]byte, len(column))
		for i, b := range column {
			decrypted[i] = b ^ byte(key)
		}

		currentScore := scoreText(decrypted)
		if currentScore > highScore {
			highScore = currentScore
			bestKey = byte(key)
		}
	}
	return bestKey
}

func c19() {
	key := getKey()
	ciphertexts := generateMany(key, input)
	for _, cipher := range ciphertexts {
		log.Printf("Cipher: %s\n", string(cipher))
	}

	maxLen := 0
	for _, c := range ciphertexts {
		if len(c) > maxLen {
			maxLen = len(c)
		}
	}

	keystream := make([]byte, maxLen)
	for i := 0; i < maxLen; i++ {
		// build transpose
		var column []byte
		for _, c := range ciphertexts {
			if i < len(c) {
				column = append(column, c[i])
			}
		}

		// compare and hope for a crack
		keystream[i] = solveSingleByteXOR(column)
	}

	// decrypt
	for _, c := range ciphertexts {
		decrypted := xor.XorBytes(c, keystream)
		log.Printf("%s\n", string(decrypted))
	}
}
