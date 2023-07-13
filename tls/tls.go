package tls

import (
	"anonpao/aesgcm"
	"anonpao/hkdf"
	"anonpao/sha2"
	"anonpao/utils"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
)

// NOTATION is from https://eprint.iacr.org/2020/1044.pdf

// Implements the HS shortcut, where the client's witness is the HS secret
// Steps:
// (1) Derive the server handshake key using the HS
// (2) Use it to decrypt the ServerFinished value from the transcript - real_SF
// (3) Derive the ServerFinished value using the purported HS - calculated_SF
// (4) Verify that the two SF values are the same
// (5) Using the HS, compute the client traffic keys and decrypt the ciphertext

// HS - handshake secret
// H2 - Hash(CH || SH)
// ServExt - server extensions (the last 36 bytes of which are the ServerFinished ext)
// ServExt_tail - the suffix of ServExt that does not fit in a whole SHA block

// Transcript TR3 = ClientHello || ServerHello || ServExt
// note that the final 36 bytes of TR3 contain the ServerFinished extension
// TR7 is TR3 without the SF extension; that is, TR7 is TR3 without the last 36 bytes

// SHA_H_Checkpoint - the H-state of SHA up to the last whole block of TR7

func Get1RTT_HS_new(HS []byte, H2, H7 []byte, CH_SH_len uint16, CH_SH []byte, ServExt_len uint16, ServExt_ct, ServExt_ct_tail []byte, ServExt_tail_len uint8, SHA_H_Checkpoint []uint32, appl_ct []byte) ([][]byte, error) {
	SHTS := hkdf.HKDF_expand_derive_secret(HS, "s hs traffic", H2)

	// traffic key and iv for "server handshake" messages
	tk_shs := hkdf.HKDF_expand_derive_tk(SHTS, 16)
	iv_shs := hkdf.HKDF_expand_derive_iv(SHTS, 12)

	log.Println("tk_shs: ", hex.EncodeToString(tk_shs))
	log.Println("iv_shs: ", hex.EncodeToString(iv_shs))

	TR3_len := CH_SH_len + ServExt_len
	TR7_len := TR3_len - uint16(36)

	ServExt := aesgcm.AES_GCM_decrypt(tk_shs, iv_shs, ServExt_ct, byte(0))

	// ServExt = ServExt_head || ServExt_tail
	// ServExt_head_length := ServExt_len - uint16(ServExt_tail_len)

	// To decrypt the ServExt_tail, we need to calculate the GCM counter block number
	// gcm_block_number := byte(ServExt_head_length / uint16(16))
	gcm_block_number := byte(ServExt_len/uint16(64)) * uint8(4)

	// Additionally, the ServExt_tail might not start perfectly at the start of a block
	// That is, the length of ServExt_head may not be a multiple of 16
	// offset := byte(ServExt_head_length % uint16(16))

	// This function decrypts the tail with the specific GCM block number and offset within the block
	ServExt_tail := aesgcm.AES_GCM_decrypt(tk_shs, iv_shs, ServExt_ct_tail, gcm_block_number)
	log.Println("ServExt_tail: ", hex.EncodeToString(ServExt_tail))

	// This transcript is CH || SH || ServExt
	TR3 := utils.Concat(CH_SH, ServExt)

	// As we don't know the true length of ServExt, the variable's size is a fixed upper bound
	// However, we only require a hash of the true transcript, which is a prefix of the variable
	// of length CH_SH_len + ServExt_len
	H3_new := sha2.SHA2(TR3)
	log.Println("H3_new: ", hex.EncodeToString(H3_new))

	// This function calculates the hash of TR3 and TR7 where TR7 is TR3 without the last 36 characters
	// starting with the SHA_H_Checkpoint provided as a checkpoint state of SHA that is common to both transcripts.
	// The inputs are:
	// - the checkpoint state
	// - the length of TR3 and TR7 (the latter must be a prefix of the former)
	// - the tail of TR3 (the suffix after the checkpoint)
	// - the length of the tail of TR3
	// - the length of the tail of TR7
	H7_H3 := sha2.Double_SHA_from_checkpoint(SHA_H_Checkpoint, TR3_len, TR7_len, ServExt_tail, ServExt_tail_len, ServExt_tail_len-byte(36))

	H_7 := H7_H3[0]
	H_3 := H7_H3[1]

	log.Println("H_7: ", hex.EncodeToString(H_7))
	log.Println("H_3: ", hex.EncodeToString(H_3))

	// Derive the SF value
	fk_S := hkdf.HKDF_expand_derive_secret(SHTS, "finished", []byte{})
	SF_calculated := hkdf.HMAC(fk_S, H7)

	// Now, we need to calculate the actual SF value present in the transcript
	// We know that SF is in the tr3_tail
	// And that it is the last 32 bytes of tr3_tail... so there are ct3_tail_length - 32 characters before it
	SF_transcript := make([]byte, 32)

	for i := 0; i < 32; i++ {
		SF_transcript[i] = ServExt_tail[i+int(ServExt_tail_len)-32]
	}

	// Verify that the two SF values are identical
	if len(SF_calculated) != len(SF_transcript) {
		return nil, errors.New("SF values are not the same length")
	}

	log.Println("SF_calculated: ", hex.EncodeToString(SF_calculated))
	log.Println("SF_transcript: ", hex.EncodeToString(SF_transcript))

	dHS := hkdf.HKDF_expand_derive_secret(HS, "derived", sha2.Hash_of_empty())

	MS := hkdf.HKDF_extract(dHS, make([]byte, 32))

	log.Println("MS: ", hex.EncodeToString(MS))

	CATS := hkdf.HKDF_expand_derive_secret(MS, "c ap traffic", H3_new)

	// client application traffic key, iv
	tk_capp := hkdf.HKDF_expand_derive_tk(CATS, 16)
	iv_capp := hkdf.HKDF_expand_derive_iv(CATS, 12)

	log.Println("tk_capp: ", hex.EncodeToString(tk_capp))
	log.Println("iv_capp: ", hex.EncodeToString(iv_capp))

	dns_plaintext := aesgcm.AES_GCM_decrypt(tk_capp, iv_capp, appl_ct, byte(0))

	// testing aesgcm
	dummy_data := []byte("hello world")
	ct := aesgcm.AES_GCM_encrypt(tk_capp, iv_capp, dummy_data, byte(0))
	pt := aesgcm.AES_GCM_decrypt(tk_capp, iv_capp, ct, byte(0))
	log.Println("pt: ", string(pt))

	// testing sha2
	dummy_data_2 := []byte("hello world 22 cxafc zxgw t32 rfdf32rfsdfsdf")
	h := sha2.SHA2(dummy_data_2)
	h2 := sha256.Sum256(dummy_data_2)
	log.Println("h: ", hex.EncodeToString(h))
	log.Println("h2: ", hex.EncodeToString(h2[:]))

	return [][]byte{dns_plaintext, tk_shs, iv_shs, tk_capp, iv_capp, H_3, SF_calculated}, nil
}
