package xor

import (
	"bufio"
	"log"
	"os"
)

func ReadAndDetect(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// optionally, resize scanner's capacity for lines over 64K, see next example
	maxScore := 0.0
	outtext := ""
	for scanner.Scan() {
		_, score, text := decryptXORInput(scanner.Text())
		if score > maxScore {
			maxScore = score
			outtext = text
		}
	}
	log.Printf("Text: %s\n", outtext)
}
