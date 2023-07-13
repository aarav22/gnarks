package hkdf

import (
	"anonpao/utils"
	"crypto/sha256"
)

// This file implements both HMAC and HKDF (RFC 5869) with SHA256 as the base hash function.
// The three main functions to implement are:
// (1) HMAC
// (2) HKDF Extract
// (3) HKDF Expand - this is a iterative function, but only one iteration is required in TLS 1.3
// The last two call HMAC after processing their inputs.
// Furthermore, TLS 1.3 uses Expand in particular ways depending on what the desired output is (a secret, key or iv)
// It also pre-processes the inputs in specific ways, such as prepending the string "tls13 " to the label

// Fixed bytes used in the HMAC function

const IPAD = 0x36
const OPAD = 0x5c

// HMAC function:
// HMAC(key, salt) = H((k \xor ipad) || H((k \xor opad)  ||  salt))
// where ipad and opad are fixed bytes (0x36 and 0x5c respective)

func HMAC(key, salt []byte) []byte {
	// the key is padded to 512 bits when using SHA256
	if len(key) < 64 {
		key_pad := make([]byte, 64-len(key))
		key = append(key, key_pad...)
	}

	// We xor every byte of the key with ipad and opad to generate the following two strings
	key_ipad := utils.XOR_with_byte(key, IPAD)
	key_opad := utils.XOR_with_byte(key, OPAD)

	// The inner of the two nested hashes
	sha256_1 := sha256.New()
	_, err := sha256_1.Write(append(key_ipad, salt...))
	if err != nil {
		panic(err)
	}

	inner_hash := sha256_1.Sum(nil)

	// convert the inner hash to a byte array
	sha256_2 := sha256.New()
	_, err = sha256_2.Write(append(key_opad, inner_hash...))
	if err != nil {
		panic(err)
	}

	// The outer of the two nested hashes
	return sha256_2.Sum(nil)
}

func HKDF_extract(salt, key []byte) []byte {
	return HMAC(salt, key)
}

// One iteration of HKDF expand, the one_byte being appending to the 'info' input
func hkdf_expand(prk, info []byte) []byte {
	one_byte := []byte{0x01}
	label := append(info, one_byte...)
	return HMAC(prk, label)
}

// This function generates the label to be used by the TLS 1.3 algorithm when calling HKDF
// The description is in RFC 8446, Section 7.1

func get_tls_hkdf_label(output_len int, label_string string, context_hash []byte) []byte {
	// Get length of the desired output represented as 2 bytes
	output_len_in_bytes := uint16(output_len)
	output_len_bytes := []byte{byte(output_len_in_bytes >> 8), byte(output_len_in_bytes)}

	// Append "tls13 " to the label string
	label_bytes := append([]byte("tls13 "), []byte(label_string)...)

	// Prepend the length of the new label represented as 1 byte
	label_len_byte := []byte{byte(6 + len(label_string))}

	// Reprsent the length of the context hash as 1 byte
	context_hash_len_byte := []byte{byte(len(context_hash))}

	// The final label is the concatenation of the following:
	// 1. length of the required output as 2 bytes
	// 2. the label prepended by its length as one byte
	// 3. the context hash prepended by its length as one byte
	arrays_to_concat := [][]byte{output_len_bytes, label_len_byte, label_bytes, context_hash_len_byte, context_hash}

	// Concatenate the arrays
	hkdf_label := []byte{}
	for _, v := range arrays_to_concat {
		hkdf_label = append(hkdf_label, v...)
	}
	return hkdf_label
}

// The three functions below call HKDF Expand
// when the output generated is a key and a iv and a TLS secret, respectively.
// Descriptions are in RFC 8446, Section 7.3

func HKDF_expand_derive_tk(secret []byte, key_length int) []byte {
	// For AES GCM 128, the key length is 16
	hkdf_label := get_tls_hkdf_label(key_length, "key", []byte{})
	return utils.Get_prefix(hkdf_expand(secret, hkdf_label), key_length)
}

func HKDF_expand_derive_iv(secret []byte, iv_length int) []byte {
	// For AES GCM 128, the iv length is 12
	hkdf_label := get_tls_hkdf_label(iv_length, "iv", []byte{})
	return utils.Get_prefix(hkdf_expand(secret, hkdf_label), iv_length)
}

func HKDF_expand_derive_secret(secret []byte, label_string string, context_hash []byte) []byte {
	// The length of all TLS 1.3 secrets are 32 bytes

	hkdf_label := get_tls_hkdf_label(32, label_string, context_hash)

	return hkdf_expand(secret, hkdf_label)
}
