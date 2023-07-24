package sha2

import (
	"anonpao/utils"
)

// The constant definitions and the compression function are taken from the xJsnark example
// with only slight modifications.

var H_CONST = []uint32{1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225}

var K_CONST = []uint64{1116352408, 1899447441, 3049323471, 3921009573, 961987163, 1508970993, 2453635748, 2870763221, 3624381080, 310598401, 607225278, 1426881987, 1925078388, 2162078206, 2614888103, 3248222580, 3835390401, 4022224774, 264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986, 2554220882, 2821834349, 2952996808, 3210313671, 3336571891, 3584528711, 113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291, 1695183700, 1986661051, 2177026350, 2456956037, 2730485921, 2820302411, 3259730800, 3345764771, 3516065817, 3600352804, 4094571909, 275423344, 430227734, 506948616, 659060556, 883997877, 958139571, 1322822218, 1537002063, 1747873779, 1955562222, 2024104815, 2227730452, 2361852424, 2428436474, 2756734187, 3204031479, 3329325298}

func rotateRight(x uint32, n uint32) uint32 {
	return (x >> n) | (x << (32 - n))
}

// This is the main SHA calling function.
func SHA2(input []uint8) []uint8 {
	if len(input) == 64 {
		return SHA2_512_length(input)
	}

	padded_input := padded_sha_input(input)
	input_in_32 := utils.Convert_8_to_32(padded_input)

	if len(input_in_32)%16 != 0 {
		panic("Padded sha must be a multiple of 512")
	}

	num_blocks := len(input_in_32) / 16

	h_value := []uint32{H_CONST[0], H_CONST[1], H_CONST[2], H_CONST[3], H_CONST[4], H_CONST[5], H_CONST[6], H_CONST[7]}

	block := make([]uint32, 16)
	for i := 0; i < num_blocks; i++ {
		for j := 0; j < 16; j++ {
			block[j] = input_in_32[i*16+j]
		}
		h_value = sha2_compression(block, h_value)
	}

	return utils.Convert_32_to_8(h_value)
}

// The next two variables were used for a minor optimization for when the padded input is just one block length
// which is 512 bits in SHA2

var PAD_FOR_512 = []uint32{2147483648, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 512}

var WORDS_FOR_512_PAD = []uint32{2147483648, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 512, 2147483648, 20971520, 2117632, 20616, 570427392, 575995924, 84449090, 2684354592, 1518862336, 6067200, 1496221, 4202700544, 3543279056, 291985753, 4142317530, 3003913545, 145928272, 2642168871, 216179603, 2296832490, 2771075893, 1738633033, 3610378607, 1324035729, 1572820453, 2397971253, 3803995842, 2822718356, 1168996599, 921948365, 3650881000, 2958106055, 1773959876, 3172022107, 3820646885, 991993842, 419360279, 3797604839, 322392134, 85264541, 1326255876, 640108622, 822159570, 3328750644, 1107837388, 1657999800, 3852183409, 2242356356}

// Function to return the hash of the empty string
func Hash_of_empty() []uint8 {
	HASH_OF_EMPTY := []uint8{227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174, 65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85}
	return HASH_OF_EMPTY
}

// The following code is written to add support for padding
// and the optimizations used in SHA explained at the top of this file.

// Returns the input appended with the pad

func padded_sha_input(input []uint8) []uint8 {
	bit_length := 8 * len(input)
	last_block_length := bit_length % 512

	num_bytes_left := (512 - last_block_length) / 8
	if num_bytes_left <= 8 {
		num_bytes_left += 64
	}

	//  8 bytes go for the length
	one_and_zeros := make([]uint8, num_bytes_left-8)
	one_and_zeros[0] = uint8(128)

	for i := 1; i < len(one_and_zeros); i++ {
		one_and_zeros[i] = 0
	}

	length_pad := make([]uint8, 8)

	bit_length_64 := uint64(bit_length)

	for i := 0; i < 8; i++ {
		length_pad[i] = uint8(bit_length_64 >> (8 * (7 - i)))
	}

	arrays_to_concat := [][]uint8{input, one_and_zeros, length_pad}

	return utils.Concat_2d(arrays_to_concat)
}

// It performs one compression of SHA when given an input of length 16 x 32 = 256
// and a "checkpoint" state H

func sha2_compression(input []uint32, H []uint32) []uint32 {
	if len(input) != 16 {
		panic("This method only accepts 16 32-bit words as inputs")
	}
	if len(H) != 8 {
		panic("This method only accepts 8 32-bit words as h_prev")
	}

	var H0, H1, H2, H3, H4, H5, H6, H7 uint32
	H0, H1, H2, H3, H4, H5, H6, H7 = H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]

	words := make([]uint32, 64)
	copy(words, input)

	// Use a lookup table for rotations
	rotate := func(x, k uint32) uint32 {
		return (x >> k) | (x << (32 - k))
	}

	for j := 16; j < 64; j++ {
		s0 := rotate(words[j-15], 7) ^ rotate(words[j-15], 18) ^ (words[j-15] >> 3)
		s1 := rotate(words[j-2], 17) ^ rotate(words[j-2], 19) ^ (words[j-2] >> 10)
		words[j] = words[j-16] + s0 + words[j-7] + s1
	}

	for j := 0; j < 64; j++ {
		s0 := rotate(H0, 2) ^ rotate(H0, 13) ^ rotate(H0, 22)
		maj := (H0 & H1) ^ (H0 & H2) ^ (H1 & H2)
		t2 := s0 + maj

		s1 := rotate(H4, 6) ^ rotate(H4, 11) ^ rotate(H4, 25)
		ch := (H4 & H5) ^ (^H4 & H6)
		t1 := H7 + s1 + ch + uint32(K_CONST[j]) + words[j]

		H7 = H6
		H6 = H5
		H5 = H4
		H4 = H3 + t1
		H3 = H2
		H2 = H1
		H1 = H0
		H0 = t1 + t2
	}

	H[0] += H0
	H[1] += H1
	H[2] += H2
	H[3] += H3
	H[4] += H4
	H[5] += H5
	H[6] += H6
	H[7] += H7

	return H
}

// Returns the length of the pad required for a given input length

func get_pad_length(input_length uint16) uint8 {

	last_block_length := uint8(input_length % uint16(64))

	var pad_length byte

	if last_block_length <= byte(55) {
		pad_length = byte(64) - last_block_length
	} else {
		pad_length = byte(128) - last_block_length
	}

	return pad_length
}

// Returns the actual pad required for a given input length

func get_pad_from_length_in_bytes(length uint16) []byte {
	pad_length := get_pad_length(length)

	input_len_in_bits := utils.Convert_64_to_8(uint64(length) * uint64(8))

	// It'll be less than 72 but 128 makes it an even multiple of 64
	pad := make([]byte, 128)

	pad[0] = byte(128)

	counter := byte(0)
	for i := 0; i < 72; i++ {
		if byte(i) < pad_length {
			if byte(i)+byte(8) >= pad_length {
				pad[i] = input_len_in_bits[counter]
				counter = counter + byte(1)
			}
		}
	}

	return pad
}

// ///////////////////////// Functions for computing the hash of a string AND a prefix of that string
// without redoing the entire computation.
// That is, we use the H_state value of the compression function of the blocks that are common
// to both the string and its prefix.

// the full string ~ "full"
// the prefix string ~ "prefix"

// H_checkpoint - H state that is common to both prefix and full string
// full_length - the total length of the full string
// prefix_length - the length of the prefix string
// full_tail - the portion of the full string past the checkpoint block
// full_tail_length
// prefix_tail_length - the length of the prefix of full_tail that belongs to the prefix string

func Double_SHA_from_checkpoint(
	H_checkpoint []uint32,
	full_length uint16, prefix_length uint16,
	full_tail_string []byte,
	full_tail_length byte,
	prefix_tail_length byte) [][]byte {

	H_checkpoint_copy_1 := make([]uint32, 8)
	H_checkpoint_copy_2 := make([]uint32, 8)

	copy(H_checkpoint_copy_1, H_checkpoint)
	copy(H_checkpoint_copy_2, H_checkpoint)

	prefix_output := SHA2_of_tail(full_tail_string, prefix_tail_length, prefix_length, H_checkpoint_copy_1)
	full_output := SHA2_of_tail(full_tail_string, full_tail_length, full_length, H_checkpoint_copy_2)
	return [][]byte{prefix_output, full_output}

}

// This function takes as input a tail string that is of length less than 128 bytes
// and a H_checkpoint
// and computes the hash of the tail with the checkpoint.
// The full string's length is given to calculate the pad.

func i32tob(val []uint32) []byte {
	r := make([]byte, 4*len(val))
	for i := uint32(0); i < uint32(len(val)); i++ {
		r[4*i] = byte((val[i] >> (24)) & 0xff)
		r[4*i+1] = byte((val[i] >> (16)) & 0xff)
		r[4*i+2] = byte((val[i] >> (8)) & 0xff)
		r[4*i+3] = byte((val[i]) & 0xff)
	}
	return r
}

func i8to32(val []byte) []uint32 {
	r := make([]uint32, len(val)/4)
	for i := 0; i < len(val)/4; i++ {
		r[i] = uint32(val[4*i])<<24 | uint32(val[4*i+1])<<16 | uint32(val[4*i+2])<<8 | uint32(val[4*i+3])
	}
	return r
}

func SHA2_of_tail(tail []byte, tail_length byte, full_length uint16, H_checkpoint []uint32) []byte {

	// Calculate the pad
	pad_len_in_bytes := get_pad_length(full_length)
	pad := get_pad_from_length_in_bytes(full_length)

	// tail_with_pad = tail || pad
	tail_with_pad := make([]byte, 128)

	// This is either 1 or 2 depending on the pad length
	num_compressions := (tail_length + pad_len_in_bytes) / byte(64)

	for i := 0; i < 128; i++ {
		if byte(i) < tail_length {
			tail_with_pad[i] = tail[i]
		} else if byte(i)-tail_length < pad_len_in_bytes {
			tail_with_pad[i] = pad[byte(i)-tail_length]
		} else {
			tail_with_pad[i] = byte(0)
		}
	}

	var output []uint32
	H_value := H_checkpoint

	block := make([]byte, 64)

	// Iterate for the maximum possible times, which is 2.
	// NOTE: input must be long enough to support maximum number of iterations
	for i := 0; i < 2; i++ {
		if byte(i) < num_compressions {
			for j := 0; j < 64; j++ {
				block[j] = tail_with_pad[i*64+j]
			}

			H_value = sha2_compression(i8to32(block), H_value)
		}
	}

	output = H_value

	return utils.Convert_32_to_8(output)
}

// Function for when the input is of length 512 bits (one SHA block)
// This just has the pad and other state values hardcoded and is slightly smaller
// Insert results - ??

// convert the above function to go:
func SHA2_512_length(input []byte) []byte {
	h_value := H_CONST
	h_value = sha2_compression(utils.Convert_8_to_32(input), h_value)
	h_value = compression_with_words(PAD_FOR_512, h_value, WORDS_FOR_512_PAD)
	return utils.Convert_32_to_8(h_value)
}

func sha2_no_pad_with_checkpoint(input []byte, H []uint32) []byte {
	input_in_32 := utils.Convert_8_to_32(input)

	if len(input_in_32)%16 != 0 {
		panic("Padded sha must be a multiple of 512")
	}

	num_blocks := len(input_in_32) / 16

	h_value := H

	block := make([]uint32, 16)
	for i := 0; i < num_blocks; i++ {
		for j := 0; j < 16; j++ {
			block[j] = input_in_32[i*16+j]
		}
		h_value = sha2_compression(block, h_value)
	}

	return utils.Convert_32_to_8(h_value)
}

func compression_with_words(input []uint32, H []uint32, words []uint32) []uint32 {
	if len(input) != 16 {
		panic("This method only accepts 16 32-bit words as inputs")
	}
	if len(H) != 8 {
		panic("This method only accepts 16 32-bit words as h_prev")
	}

	// uint_32[] H = uint_32(H_CONST);

	a := H[0]
	b := H[1]
	c := H[2]
	d := H[3]
	e := H[4]
	f := H[5]
	g := H[6]
	h := H[7]

	for j := 0; j < 64; j++ {
		s0 := rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22)
		maj := (a & b) ^ (a & c) ^ (b & c)
		t2 := s0 + maj

		s1 := rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25)
		ch := e&f ^ ^e&g
		// the uint_32(.) call is to convert from java type to xjsnark type
		t1 := h + s1 + ch + uint32(K_CONST[j]) + words[j]
		h = g
		g = f
		f = e
		e = d + t1
		d = c
		c = b
		b = a
		a = t1 + t2
	}

	H[0] = H[0] + a
	H[1] = H[1] + b
	H[2] = H[2] + c
	H[3] = H[3] + d
	H[4] = H[4] + e
	H[5] = H[5] + f
	H[6] = H[6] + g
	H[7] = H[7] + h

	return H
}

// Performs the specified number of sha2 compression calls on the given input
func perform_compressions(input []byte, num_compressions byte) []uint32 {
	return perform_compressions_general(input, num_compressions, H_CONST)
}

// The above, but with an arbitary H-state
func perform_compressions_general(input []byte, num_compressions byte, H_checkpoint []uint32) []uint32 {
	// rewrite above function here:
	h_value := H_checkpoint
	block := make([]uint8, 64)

	// Iterate for the maximum possible times that may be required depending on the maximum input length
	// NOTE: input must be long enough to support maximum number of iterations

	max_compressions := len(input) / 64
	for i := 0; i < max_compressions; i++ {
		if byte(i) < num_compressions {
			for j := 0; j < 64; j++ {
				block[j] = input[i*64+j]
			}
			h_value = sha2_compression(utils.Convert_8_to_32(block), h_value)
		}
	}
	return h_value

}

// Given an input string, a length and a final block
// this function returns the hash of the first l bytes of the input
// The final block is provided as auxiliary input to optimize the final circuit.
func SHA2_of_prefix(input []byte, tr_len_in_bytes uint16, last_block []byte) []byte {
	output := make([]byte, 32)
	pad_len_in_bytes := get_pad_length(tr_len_in_bytes)
	pad := get_pad_from_length_in_bytes(tr_len_in_bytes)

	last_block_len := byte(tr_len_in_bytes % uint16(64))

	num_base_compressions := byte(tr_len_in_bytes / uint16(64))

	H_value_base := perform_compressions(input, num_base_compressions)

	last_blocks_padded := make([]byte, 128)
	last_block_padded := make([]byte, 64)

	if pad_len_in_bytes > byte(64) {
		for i := 0; i < 64; i++ {
			if byte(i) < last_block_len {
				last_blocks_padded[i] = last_block[i]
			} else {
				last_blocks_padded[i] = pad[byte(i)-last_block_len]
			}
		}

		for i := 64; i < 128; i++ {
			last_blocks_padded[i] = pad[byte(i)-last_block_len]
		}

		output = sha2_no_pad_with_checkpoint(last_blocks_padded, H_value_base)

	} else {
		for i := 0; i < 64; i++ {
			if byte(i) < last_block_len {
				last_block_padded[i] = last_block[i]
			} else {
				last_block_padded[i] = pad[byte(i)-last_block_len]
			}
		}

		output = sha2_no_pad_with_checkpoint(last_block_padded, H_value_base)

	}
	return output

}
