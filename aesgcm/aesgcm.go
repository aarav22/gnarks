package aesgcm

import (
	"anonpao/utils"
)

// returns the bytes of 'iv || index' for the given block_number
func get_block_iv_8(iv []byte, block_num byte) []byte {
	block_iv := make([]byte, 16)

	for i := 0; i < 12; i++ {
		block_iv[i] = iv[i]
	}

	for i := 12; i < 16; i++ {
		block_iv[i] = byte(uint32(block_num+byte(2)) >> (8 * (15 - i)))
	}

	return block_iv
}

// same as above but the block_number is given as uint_8
func get_block_iv(iv []byte, block_num int) []byte {
	return get_block_iv_8(iv, byte(block_num))
}

func AES_GCM_encrypt(key, iv, plaintext []byte, starting_block byte) []byte {
	len_in_bytes := len(plaintext)
	num_blocks := (len_in_bytes / 16)
	if len_in_bytes%16 != 0 {
		num_blocks += 1
	}

	expandedKey := expandKey(key)

	// This part contains the operations required for GCM

	block_iv := make([]byte, 16)
	output := make([]byte, 0)

	for i := 0; i < num_blocks; i++ {
		block_iv = get_block_iv_8(iv, byte(i)+starting_block)

		iv_cipher := encrypt_expanded(expandedKey, block_iv)

		output = utils.Concat(output, iv_cipher)

	}
	return utils.XOR_arrays_prefix(plaintext, output, len(plaintext))
}

func AES_GCM_decrypt(key, iv, ciphertext []byte, starting_block byte) []byte {
	return AES_GCM_encrypt(key, iv, ciphertext, starting_block)
}

// This peculiar function decrypts two blocks of ciphertext
// with the pad generated at block number starting_block
// and at an offset of length offset within that starting block.
// This is used at one point in the TLS Key Schedule Shortcut method

func AES_GCM_decrypt_128bytes_middle(key []byte, iv []byte, ciphertext []byte, starting_block byte, offset byte) []byte {
	zero_plaintext := make([]byte, 144)

	pad := AES_GCM_decrypt(key, iv, zero_plaintext, starting_block)

	pad_offset := make([]byte, 128)

	for i := 0; i < 128; i++ {
		pad_offset[i] = pad[byte(i)+offset]
	}

	return utils.Xor_arrays_prefix(ciphertext, pad_offset, 128)
}

// The following functions are from the aes example file from xJsnark
// with only slight modifications.

var SBOX = []uint8{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}

var RCON = []uint8{0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36}
var nb = 4
var nk = 4

func expandKey(key []byte) []byte {
	nr := nk + 6
	expandedKey := make([]byte, nb*(nr+1)*4)
	w := make([][]byte, nb*(nr+1))
	var tmp []byte
	i := 0
	for i < nk {
		w[i] = []byte{key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]}
		i++
	}
	for tmp_idx := i; tmp_idx < nb*(nr+1); tmp_idx++ {
		w[tmp_idx] = []byte{0, 0, 0, 0}
	}

	for i < nb*(nr+1) {
		tmp = w[i-1]
		if i%nk == 0 {
			tmp = rotWord(tmp)
			tmp = subWord(tmp)
			tmp[0] = tmp[0] ^ byte(RCON[i/4])
		}
		for v := 0; v < 4; v++ {
			w[i][v] = w[i-nk][v] ^ tmp[v]
		}
		i++
	}
	idx := 0
	for k := 0; k < nb*(nr+1); k++ {
		for j := 0; j < 4; j++ {
			expandedKey[idx] = w[k][j]
			idx++
		}
	}
	return expandedKey
}

func subWord(w []byte) []byte {
	newW := make([]byte, len(w))
	for j := 0; j < len(w); j++ {
		newW[j] = SBOX[w[j]]
	}
	return newW
}

func rotWord(w []byte) []byte {
	newW := make([]byte, len(w))
	for j := 0; j < len(w); j++ {
		newW[j] = w[(j+1)%len(w)]
	}
	return newW
}

func subState(state [][]byte) [][]byte {
	newState := make([][]byte, len(state))
	for i := 0; i < len(state); i++ {
		newState[i] = make([]byte, len(state[i]))
		for j := 0; j < len(state[i]); j++ {
			newState[i][j] = SBOX[state[i][j]]
		}
	}
	return newState
}

func gal_mul_const(x byte, c int) byte {
	p := byte(0)
	for counter := 0; counter < 8; counter += 1 {
		if (c & 1) != 0 {
			p = p ^ x
		}
		c = c >> 1
		if c == 0 {
			break
		}
		hi := x >> 7
		x = x << 1
		tmp := x ^ 0x1b
		if hi != 0 {
			x = tmp
		}
	}
	return p
}

func shiftRows(state [][]byte) [][]byte {
	newState := make([][]byte, len(state))
	for i := 0; i < len(state); i++ {
		newState[i] = make([]byte, len(state[i]))
		for j := 0; j < len(state[i]); j++ {
			newState[i][j] = state[i][(j+i)%len(state[i])]
		}
	}
	return newState
}

func mixColumns(state [][]byte) [][]byte {
	a := make([]byte, 4)
	newState := make([][]byte, len(state))
	for i := 0; i < len(state); i++ {
		newState[i] = make([]byte, len(state[i]))
	}

	for c := 0; c < 4; c++ {
		for i := 0; i < 4; i++ {
			a[i] = state[i][c]
		}
		newState[0][c] = gal_mul_const(a[0], 2) ^ gal_mul_const(a[1], 3) ^ a[2] ^ a[3]
		newState[1][c] = a[0] ^ gal_mul_const(a[1], 2) ^ gal_mul_const(a[2], 3) ^ a[3]
		newState[2][c] = a[0] ^ a[1] ^ gal_mul_const(a[2], 2) ^ gal_mul_const(a[3], 3)
		newState[3][c] = gal_mul_const(a[0], 3) ^ a[1] ^ a[2] ^ gal_mul_const(a[3], 2)
	}
	return newState
}

func addRoundkey(expandedKey []byte, state [][]byte, from int, to int) [][]byte {
	newState := make([][]byte, len(state))
	for i := 0; i < len(state); i++ {
		newState[i] = make([]byte, len(state[i]))
	}

	idx := 0
	for j := 0; j < 4; j++ {
		for i := 0; i < 4; i++ {
			newState[i][j] = state[i][j] ^ expandedKey[from+idx]
			idx++
		}
	}
	return newState
}

func aes_encrypt(key []byte, plaintext []byte) []byte {
	expandedKey := expandKey(key)
	return encrypt_expanded(expandedKey, plaintext)
}

func encrypt_expanded(expandedKey []byte, plaintext []byte) []byte {
	ciphertext := make([]byte, len(plaintext))
	state := make([][]byte, 4)
	for i := 0; i < 4; i++ {
		state[i] = []byte{0, 0, 0, 0}
	}

	idx := 0
	for j := 0; j < 4; j++ {
		for k := 0; k < 4; k++ {
			state[k][j] = plaintext[idx]
			idx++
		}
	}
	state = addRoundkey(expandedKey, state, 0, 3)
	nr := 6 + nk
	for round := 1; round < nr; round++ {
		state = subState(state)
		state = shiftRows(state)
		state = mixColumns(state)
		state = addRoundkey(expandedKey, state, round*4*4, (round+1)*4*4-1)
		// Note: the methods substate(), shiftRows(), mixColumns(), addRoundKey() could be also be
		// written in a way that updates the state array directly in place.
	}
	state = subState(state)
	state = shiftRows(state)
	state = addRoundkey(expandedKey, state, nr*4*4, (nr+1)*4*4-1)

	idx = 0
	for j := 0; j < 4; j++ {
		for k := 0; k < 4; k++ {
			ciphertext[idx] = state[k][j]
			idx++
		}
	}

	return ciphertext
}
