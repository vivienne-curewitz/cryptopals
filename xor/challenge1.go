package xor

const padChar = '='

// I will just use the standard lib for the rest of the exercises :)
func EncodeB64(dst, src []byte) {
	var encode = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
	if len(src) == 0 {
		return
	}
	di, si := 0, 0
	// largest multiple of 3 <= len(src)
	n := (len(src) / 3) * 3
	for si < n {
		// Convert 3x 8bit source bytes into 4 bytes
		val := uint(src[si+0])<<16 | uint(src[si+1])<<8 | uint(src[si+2])

		// 3 x 8 becomes 4 x 6
		dst[di+0] = encode[val>>18&0x3F]
		dst[di+1] = encode[val>>12&0x3F]
		dst[di+2] = encode[val>>6&0x3F]
		dst[di+3] = encode[val&0x3F]

		si += 3
		di += 4
	}

	remain := len(src) - si
	if remain == 0 {
		return
	}
	// Add the remaining small block
	// always the first, sometimes the second
	val := uint(src[si+0]) << 16
	if remain == 2 {
		val |= uint(src[si+1]) << 8
	}

	// the same convert as before
	dst[di+0] = encode[val>>18&0x3F]
	dst[di+1] = encode[val>>12&0x3F]

	switch remain {
	case 2:
		dst[di+2] = encode[val>>6&0x3F]
		dst[di+3] = byte(padChar)
	case 1:
		dst[di+2] = byte(padChar)
		dst[di+3] = byte(padChar)
	}
}
