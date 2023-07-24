package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strconv"

	"anonpao/tls"
	"anonpao/utils"
)

// Input line is assumed to be the hex representation of a byte string S
// Consider string (S-36), which is S without the last 36 bytes.
// Divide (S-36) into whole SHA blocks (with some leftover suffix)
// The output of this function is the suffix of S (and not of S-36)
// that does not fit into a whole block.

func get_tail_minus_36(line string) string {
	output := ""
	len := (len(line) / 2)
	block_size := 64 // for SHA2
	num_whole_blocks := (len - 36) / block_size
	tail_len := len - num_whole_blocks*block_size
	// log.Println("tail_len: ", tail_len, "num_whole_blocks: ", num_whole_blocks, "len: ", len, (len-36)%block_size)
	for i := 0; i < tail_len; i++ {
		j := num_whole_blocks*block_size + i
		output = output + line[2*j:2*j+2]
	}
	return output
}

// Outputs the part of the input that doesn't fit into a whole SHA2 block
func get_last_block(line string) string {
	output := ""
	len := len(line) / 2

	block_size := 64
	num_whole_blocks := len / block_size
	lbl := len % block_size
	// log.Println("lbl: ", lbl, "num_whole_blocks: ", num_whole_blocks, "len: ", len)

	for i := 0; i < lbl; i++ {
		j := num_whole_blocks*64 + i
		output = output + line[2*j:2*j+2]
	}

	for i := lbl; i < 64; i++ {
		output = output + "00"
	}

	return output
}

func main() {

	values := []string{}

	// read test_doh.txt
	f, err := os.Open("test_doh.txt")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	// now read line by line:
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		values = append(values, scanner.Text())
	}
	// psk := values[0]
	// sk := values[1]
	// Ax := values[2]
	// Ay := values[3]
	// Bx := values[4]
	// By := values[5]
	HS_line := values[6] // Handshake secret
	H2_line := values[7] // Hash(CH || SH)
	H7_line := values[8] // Hash(CH || SH || Extensions_without_SF_value)
	// H3 := values[9]   // Hash(CH || SH || Extensions_with_SF_value)
	// SF := values[10]  // ServerFinished
	ch_sh_line := values[11] // ClientHello || ServerHello
	ext_line := values[12]   // EncryptedServerExtensions: Enc(Certificate || CertificateVerify || SF)
	dns_ct := values[13]
	H_state_tr7_line := values[14]

	// ct3_tail_str is the part of ct3 that doesn't fit into a whole SHA block
	// ct3_tail_str := get_tail_minus_36(ch_sh_line + ext_line)

	ct_lb := get_tail_minus_36(ch_sh_line + ext_line)
	// log.Println("ct_lb: ", ct_lb, "len: ", len(ct_lb)/2)

	// print all the lines
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	// log.Println("HS: ", len(HS_line)/2)

	http_msg_ciphertext := make([]uint8, 500)
	H_state_tr7 := make([]uint8, 32)
	HS := make([]uint8, 32)
	H2 := make([]uint8, 32)
	H7 := make([]uint8, 32)
	ch_sh := make([]uint8, len(ch_sh_line)/2)
	ServExt_ct := make([]uint8, len(ext_line)/2)
	// This auxiliary input helps compute the hash of TR3 efficiently
	// The tail is the suffix of the Extensions that does not fit inside a whole SHA block (64 bytes long)
	ServExt_ct_tail := make([]uint8, 128)

	ch_sh_len := uint16(len(ch_sh_line) / 2)
	ServExt_ct_len := uint16(len(ext_line) / 2)
	ServExt_ct_tail_len := uint8(len(ct_lb) / 2)

	// conversions:
	for i := 0; i < len(HS_line)/2; i++ {
		ui64, _ := strconv.ParseUint(HS_line[2*i:2*i+2], 16, 8)
		HS[i] = uint8(ui64)
	}

	for i := 0; i < len(H2_line)/2; i++ {
		ui64, _ := strconv.ParseUint(H2_line[2*i:2*i+2], 16, 8)
		H2[i] = uint8(ui64)
	}

	for i := 0; i < len(H7_line)/2; i++ {
		ui64, _ := strconv.ParseUint(H7_line[2*i:2*i+2], 16, 8)
		H7[i] = uint8(ui64)
	}

	for i := 0; i < len(ch_sh_line)/2; i++ {
		ui64, _ := strconv.ParseUint(ch_sh_line[2*i:2*i+2], 16, 8)
		ch_sh[i] = uint8(ui64)
	}

	for i := 0; i < len(ext_line)/2; i++ {
		ui64, _ := strconv.ParseUint(ext_line[2*i:2*i+2], 16, 8)
		ServExt_ct[i] = uint8(ui64)
	}

	for i := 0; i < len(ct_lb)/2; i++ {
		ui64, _ := strconv.ParseUint(ct_lb[2*i:2*i+2], 16, 8)
		ServExt_ct_tail[i] = uint8(ui64)
	}

	// for i := 0; i < len(ct3_tail_str)/2; i++ {
	// 	ui64, _ := strconv.ParseUint(ct3_tail_str[2*i:2*i+2], 16, 16)
	// 	ct3_tail[i] = uint8(ui64) // correction? Changed from uint16 to uint8
	// }

	// for i := len(ct3_tail_str) / 2; i < 128; i++ {
	// 	ct3_tail[i] = uint8(0)
	// }

	for i := 0; i < len(H_state_tr7_line)/2; i++ {
		ui64, _ := strconv.ParseUint(H_state_tr7_line[2*i:2*i+2], 16, 16)
		H_state_tr7[i] = uint8(ui64)
	}

	for i := 0; i < len(dns_ct)/2; i++ {
		ui64, _ := strconv.ParseUint(dns_ct[2*i:2*i+2], 16, 16)
		http_msg_ciphertext[i] = uint8(ui64)
	}

	for i := len(dns_ct) / 2; i < 500; i++ { // 500 <- HTTPFirewall.HTTP_REQUEST_MAX_LENGTH
		http_msg_ciphertext[i] = 0
	}

	// now run the TLS Key Schedule
	H_state_tr7_32 := utils.Convert_8_to_32(H_state_tr7)
	// for i := 0; i < 8; i++ {
	// 	// log.Println("H_state_tr7_32: ", H_state_tr7_32[i])
	// 	log.Print(", ", hex.EncodeToString(utils.Convert_32_to_8(H_state_tr7_32))[i*8:(i+1)*8])
	// }
	// log.Println("H_state_tr7: ", hex.EncodeToString(H_state_tr7))
	// log.Println("H_state_tr7_32 ", hex.EncodeToString(utils.Convert_32_to_8(H_state_tr7_32)))

	newvalues, err := tls.Get1RTT_HS_new(
		HS, H2, H7,
		ch_sh_len, ch_sh,
		ServExt_ct_len, ServExt_ct,
		ServExt_ct_tail, ServExt_ct_tail_len,
		H_state_tr7_32, http_msg_ciphertext)

	if err != nil {
		fmt.Println("Error in TLS Key Schedule", err)
	}

	// log.Println("H_state_tr7_32 ", hex.EncodeToString(utils.Convert_32_to_8(H_state_tr7_32)))

	plaintext := newvalues[0]
	cr_int := 0x0d
	lf_int := 0x0a

	cr := uint16(cr_int)
	lf := uint16(lf_int)

	log.Println()
	plaintext_hex := hex.EncodeToString(plaintext)
	log.Println("Plaintext hex: ", plaintext_hex)

	// convert plaintext to hex

	// find the index of the first crlf
	var crlf_index uint16
	for i := 1; i < len(plaintext); i++ {
		curr_char := uint16(plaintext[i])
		prev_char := uint16(plaintext[i-1])
		curr_concat := (prev_char << 8) | curr_char
		if curr_concat == (cr<<8)|lf {
			crlf_index = uint16(i)
			log.Println("CRLF index: ", crlf_index)
		}
	}
	// log.Println("Type of plaintext: ", reflect.TypeOf(plaintext))
	// fmt.Println("New values: ", newvalues[0])
}

// private witnesses
//  1. Handshake secret HS
//  2. SHA_H_Checkpoint - the H-state of SHA up to the last whole block of TR7

// public witnesses
//  1. transcript hash H2 = hash( CH || SH)
//  2. length of ClientHello || ServerHello
//  3. length of the Server Extensions
//  4. the suffix of TR3 that is after the checkpoint block
// which is the last whole SHA block that fits in TR7
//  5. length of the above
//  6. the application data sent

// run TLS Key Schedule to decrypt:
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
