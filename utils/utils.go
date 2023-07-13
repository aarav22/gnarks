package utils

// utils:
func Concat_2d(inputs [][]byte) []byte {
	output := inputs[0]
	for i := 1; i < len(inputs); i++ {
		output = append(output, inputs[i]...)
	}
	return output
}

func Concat(a1, a2 []byte) []byte {
	len1 := len(a1)
	len2 := len(a2)
	output := make([]byte, len1+len2)

	for i := 0; i < len1; i++ {
		output[i] = a1[i]
	}

	for i := 0; i < len2; i++ {
		output[i+len1] = a2[i]
	}
	return output
}

func XOR_arrays_prefix(a1, a2 []byte, lenparam int) []byte {
	if len(a1) < lenparam || len(a2) < lenparam {
		panic("Arrays to XOR aren't long enough")
	}

	output := make([]byte, lenparam)
	for i := 0; i < lenparam; i++ {
		output[i] = a1[i] ^ a2[i]
	}
	return output
}

// xor_with_byte takes a byte array and xors every byte with the given byte
func XOR_with_byte(input []byte, b byte) []byte {
	xored := make([]byte, len(input))
	for i, v := range input {
		xored[i] = v ^ b
	}
	return xored
}

func Get_prefix(input []byte, prefix_length int) []byte {
	output := make([]byte, prefix_length)

	for i := 0; i < prefix_length; i++ {
		output[i] = input[i]
	}
	return output
}

func CheckError(err error) {
	if err != nil {
		panic(err)
	}
}

// output = a1 || a2 || a3 || a4 || a5 || a6 || a7 || a8
func Combine_four_bytes_to_one_32(a1, a2, a3, a4 uint32) uint32 {
	return (a1 << 24) | (a2 << 16) | (a3 << 8) | a4
}

func Convert_8_to_32(input []byte) []uint32 {
	if len(input)%4 != 0 {
		panic("This method only accepts multiple of 4 in bytes.")
	}

	len_in_32 := len(input) / 4
	output := make([]uint32, len_in_32)

	for i := 0; i < len_in_32; i++ {
		output[i] = Combine_four_bytes_to_one_32(uint32(input[4*i]), uint32(input[4*i+1]), uint32(input[4*i+2]), uint32(input[4*i+3]))
	}

	return output
}
func Convert_32_to_8(input []uint32) []byte {
	output := make([]byte, len(input)*4)

	for i := 0; i < len(input); i++ {
		output[4*i] = byte(input[i] >> 24)
		output[4*i+1] = byte(input[i] >> 16)
		output[4*i+2] = byte(input[i] >> 8)
		output[4*i+3] = byte(input[i])
	}

	return output
}
func Convert_64_to_8(input uint64) []byte {
	output := make([]byte, 8)
	for i := 0; i < 8; i++ {
		output[i] = uint8(input >> ((7 - i) * 8))
	}
	return output
}

func Xor_arrays_prefix(a1, a2 []byte, length int) []byte {
	if len(a1) < length || len(a2) < length {
		panic("Arrays to XOR aren't long enough")
	}

	res := make([]byte, length)
	for i := 0; i < length; i++ {
		res[i] = a1[i] ^ a2[i]
	}
	return res
}
