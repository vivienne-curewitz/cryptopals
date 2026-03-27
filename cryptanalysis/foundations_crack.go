package cryptanalysis

import (
	"log"
	"math"
	"math/rand/v2"
	"slices"
	"sort"
)

type FrequencyData struct {
	Character byte
	Frequency float64
}

var frequencies = []FrequencyData{
	{' ', 18.00}, // Approximate frequency of a space in typical text
	{'E', 12.02},
	{'T', 9.10},
	{'A', 8.12},
	{'O', 7.68},
	{'I', 7.31},
	{'N', 6.95},
	{'S', 6.28},
	{'R', 6.02},
	{'H', 5.92},
	{'D', 4.32},
	{'L', 3.98},
	{'U', 2.88},
	{'C', 2.71},
	{'M', 2.61},
	{'F', 2.30},
	{'Y', 2.11},
	{'W', 2.09},
	{'G', 2.03},
	{'P', 1.82},
	{'B', 1.49},
	{'V', 1.11},
	{'K', 0.69},
	{'X', 0.17},
	{'Q', 0.11},
	{'J', 0.10},
	{'Z', 0.07},
}

func normalize_freq_data(z_spec bool) map[byte]float64 {
	var freq_map map[byte]float64 = make(map[byte]float64, 26)
	if z_spec {
		var space FrequencyData
		for _, fd := range frequencies {
			if fd.Character == byte(' ') {
				space = fd
				freq_map[fd.Character] = fd.Frequency
				// } else if fd.Character == 'Z' {
				// 	freq_map[fd.Character] = fd.Frequency + space.Frequency
			} else {
				freq_map[fd.Character] = fd.Frequency
			}
		}
		delta := (100.0 - space.Frequency) / 100.0
		for k, f := range freq_map {
			if k != ' ' {
				freq_map[k] = (f * delta) / 100
			} else {
				freq_map[k] = f / 100.0
			}
		}
	} else {
		for _, fd := range frequencies {
			if fd.Character != byte(' ') {
				freq_map[fd.Character] = fd.Frequency / 100.0
			}
		}
	}

	return freq_map
}

func score_text_freq(frequency_map map[byte]float64, decrypted []byte) float64 {
	found_freq := make(map[byte]float64, 26)
	for _, b := range decrypted {
		found_freq[b] += 1
	}
	for k, v := range found_freq {
		found_freq[k] = v / float64(len(decrypted))
	}
	mean_squared_error := 0.0
	for k, v := range frequency_map {
		mean_squared_error += math.Pow(v-found_freq[k], 2)
	}
	return mean_squared_error
}

func ceaser_shift(cipher []byte, b byte) []byte {
	var plain []byte = make([]byte, len(cipher))
	shift := b - 'A'
	for i := range len(cipher) {
		plain[i] = ((cipher[i] - 'A' - shift + 26) % 26) + 'A'
	}
	return plain
}

func ceaser_search(cipher []byte, fm map[byte]float64) byte {
	var b byte
	var best_b byte
	var lowest_error float64 = math.MaxFloat64
	var plain []byte = make([]byte, len(cipher))
	for b = 'A'; b <= 'Z'; b += 1 {
		shift := b - 'A'
		for i := range len(cipher) {
			plain[i] = ((cipher[i] - 'A' - shift + 26) % 26) + 'A'
		}
		mse := score_text_freq(fm, plain)
		if mse < lowest_error {
			lowest_error = mse
			best_b = b
		}
	}
	return best_b
}

func Vigenere_crack(cipher []byte) []byte {
	key_len := Kasiski_search(cipher)
	trans := make([][]byte, key_len)
	for i := range len(cipher) {
		trans[i%key_len] = append(trans[i%key_len], cipher[i])
	}
	key := make([]byte, key_len)
	fm := normalize_freq_data(false)
	for i, row := range trans {
		key[i] = ceaser_search(row, fm)
	}
	return key
}

func Vigenere_Relative(cipher []byte, key_len int) []byte {
	key_len = Kasiski_search(cipher)
	log.Printf("Key Len: %d\n", key_len)
	trans := make([][]byte, key_len)
	for i := range len(cipher) {
		trans[i%key_len] = append(trans[i%key_len], cipher[i])
	}
	relative_freq := make(map[byte]float64, len(trans[0]))
	for _, b := range trans[0] {
		relative_freq[b] += 1.0 / float64(len(trans[0]))
	}
	highest := 0.0
	var syncByte byte
	for k, v := range relative_freq {
		if v > highest {
			highest = v
			syncByte = k
		}
	}
	key := make([]byte, key_len)
	for i, row := range trans {
		if i == 0 {
			key[i] = 'Z'
		} else {
			freq := make(map[byte]float64)
			for _, b := range row {
				freq[b] += 1.0 / float64(len(row))
			}
			highest := 0.0
			var kv byte
			for k, v := range freq {
				if v > highest {
					highest = v
					kv = k
				}
			}
			shift := (((kv-syncByte)-'A')+26)%26 + 'A'
			key[i] = shift
		}
	}
	return key
}

func Strip_text(text []byte) []byte {
	var result []byte
	for _, b := range text {
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') {
			result = append(result, b)
		}
	}
	return result
}

func get_fd_from_map(fm map[byte]float64) []FrequencyData {
	fd := make([]FrequencyData, 0)
	for k, v := range fm {
		fd = append(fd, FrequencyData{
			Frequency: v,
			Character: k,
		})
	}
	return fd
}

func sortFD_slice(fd []FrequencyData) []FrequencyData {
	sort.Slice(fd, func(i, j int) bool {
		return fd[i].Frequency > fd[j].Frequency
	})
	return fd
}

func generate_substitution_key(cipher []byte) []byte {
	found_freq := make(map[byte]float64, len(cipher))
	for _, b := range cipher {
		found_freq[b] += 1.0 / float64(len(cipher))
	}
	// sorted_base := sortFD_slice(frequencies)
	sorted_base := sortFD_slice(get_fd_from_map(normalize_freq_data(false)))
	sorted_found := sortFD_slice(get_fd_from_map(found_freq))

	key := make([]byte, 26)
	for i := range len(sorted_base) {
		char_base := sorted_base[i].Character
		char_found := sorted_found[i].Character
		k_ind := char_found - 'A'
		key[k_ind] = char_base
	}
	return key
}

func Substitution_hill_climb(iteration int, cipher []byte) []byte {
	fm := normalize_freq_data(false)
	key := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	best_score := math.MaxFloat64
	var best_key []byte = slices.Clone(key)
	for _ = range iteration {
		s1_ind := rand.IntN(26)
		s2_ind := rand.IntN(26)
		for s2_ind == s1_ind {
			s2_ind = rand.IntN(26)
		}
		temp := key[s1_ind]
		key[s1_ind] = key[s2_ind]
		key[s2_ind] = temp
		to_score := Substitution_cypher(key, cipher)
		score := score_text_freq(fm, to_score)
		if score <= best_score {
			best_score = score
			best_key = slices.Clone(key)
		} else {
			key = slices.Clone(best_key)
		}
	}
	return best_key
}
