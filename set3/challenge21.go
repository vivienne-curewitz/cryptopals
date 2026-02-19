package set3

const _n = 624
const _m = 397
const _w = 32
const _r = 31
const _UMASK = uint32(0x80000000)
const _LMASK = uint32(0x7fffffff)
const _a = 0x9908b0df
const _u = 11
const _s = 7
const _t = 15
const _l = 18
const _b = 0x9d2c5680
const _c = 0xefc60000
const _f = 1812433253

type MTRand struct {
	state_array []uint32
	state_index int
}

func NewMTRand() *MTRand {
	return &MTRand{
		state_array: make([]uint32, _n),
	}
}

func (mtr *MTRand) initialize_state(seed uint32) {
	mtr.state_array[0] = seed
	var i uint32
	for i = range _n {
		seed = _f*(seed^(seed>>(_w-2))) + i
		mtr.state_array[i] = seed
	}
	mtr.state_index = 0
}

func (mtr *MTRand) rand_int() uint32 {
	k := mtr.state_index
	j := k - (_n - 1)
	if j < 0 {
		j += _n
	}
	x := (mtr.state_array[k] & _UMASK) | (mtr.state_array[j] & _LMASK)
	xA := x >> 1
	if (x & 0x00000001) != 0 {
		xA ^= _a
	}
	j = k - (_n - _m)
	if j < 0 {
		j += _n
	}
	x = mtr.state_array[j] ^ xA
	k += 1
	if k >= _n {
		k = 0
	}
	mtr.state_array[k] = x
	mtr.state_index = k
	y := x ^ (x >> _u)
	y = y ^ ((y << _s) & _b)
	y = y ^ ((y << _t) & _c)
	z := y ^ (y >> _l)

	return z
}

func (mtr *MTRand) getKeyStream(num_keys int) []byte {
	buffer := make([]byte, 4)
	keys := make([]byte, num_keys)
	for i := range num_keys {
		if i%4 == 0 {
			nv := mtr.rand_int()
			buffer[0] = byte(nv & 0x000000ff)
			buffer[1] = byte((nv >> 8) & 0x000000ff)
			buffer[2] = byte((nv >> 16) & 0x000000ff)
			buffer[3] = byte((nv >> 24) & 0x000000ff)
		}
		keys[i] = buffer[i%4]
	}
	return keys
}
