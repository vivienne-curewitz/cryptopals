package set3

// y = x ^ (x >> shift)
func undoRightShiftXor(y uint32, shift uint) uint32 {
	var x uint32
	for i := 0; i < 32; i++ {
		pos := 31 - i
		bit := (y >> pos) & 1
		if i >= int(shift) {
			dep := (x >> (pos + int(shift))) & 1
			bit ^= dep
		}
		x |= bit << pos
	}
	return x
}

// y = x ^ (x << shift) & mask
func undoLeftShiftXorMask(y uint32, shift uint, mask uint32) uint32 {
	var x uint32
	for i := 0; i < 32; i++ {
		bit := (y >> i) & 1
		if i >= int(shift) {
			if (mask>>i)&1 == 1 {
				bit ^= (x >> (i - int(shift))) & 1
			}
		}
		x |= bit << i
	}
	return x
}

func untemper(y uint32) uint32 {
	y = undoRightShiftXor(y, _l)
	y = undoLeftShiftXorMask(y, _t, _c)
	y = undoLeftShiftXorMask(y, _s, _b)
	y = undoRightShiftXor(y, _u)
	return y
}

func CloneMTR() ([]uint32, *MTRand, *MTRand) {
	seed := 1234
	mtrBase := NewMTRand()
	mtrBase.initialize_state(uint32(seed))
	outputs := make([]uint32, _n)
	for i := range len(outputs) {
		outputs[i] = mtrBase.rand_int()
	}
	cloned := NewMTRand()
	for i := range len(outputs) {
		cloned.state_array[i] = untemper(outputs[i])
	}
	cloned.state_index = _n - 1
	return outputs, cloned, mtrBase
}
