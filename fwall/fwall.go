package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"reflect"
	"strconv"

	"anonpao/tls"
	"anonpao/utils"
)

func get_tail_minus_36(line string) string {
	output := ""
	len := (len(line) / 2)
	num_whole_blocks := (len - 36) / 64
	tail_len := len - num_whole_blocks*64
	for i := 0; i < tail_len; i++ {
		j := num_whole_blocks*64 + i
		output = output + line[2*j:2*j+2]
	}
	return output
}

func main() {

	values := []string{}

	// read test_doh.txt
	f, err := os.Open("new_doh.txt")
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
	HS_line := values[6]
	H2_line := values[7]
	H7_line := values[8]
	// H3 := values[9]
	// SF := values[10]
	pt2_line := values[11]
	ct3_line := values[12]
	dns_ct := values[13]
	H_state_tr7_line := values[14]

	ct3_tail_str := get_tail_minus_36(pt2_line + ct3_line)

	// print all the lines
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	log.Println("HS: ", len(HS_line)/2)
	for i := 0; i < len(HS_line)/2; i++ {
		fmt.Print(HS_line[i])
	}

	http_msg_ciphertext := make([]uint8, 500)
	H_state_tr7 := make([]uint8, 32)
	HS := make([]uint8, 32)
	H2 := make([]uint8, 32)
	H7 := make([]uint8, 32)
	ct3_tail := make([]uint8, 128)
	pt2 := make([]uint8, len(pt2_line)/2)
	ct3 := make([]uint8, len(ct3_line)/2)

	pt2_len := uint16(len(pt2) / 2)
	ct3_len := uint16(len(ct3) / 2)
	ct3_tail_len := uint8(len(ct3_tail_str) / 2)

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

	for i := 0; i < len(pt2_line)/2; i++ {
		ui64, _ := strconv.ParseUint(pt2_line[2*i:2*i+2], 16, 8)
		pt2[i] = uint8(ui64)
	}

	for i := 0; i < len(ct3_line)/2; i++ {
		ui64, _ := strconv.ParseUint(ct3_line[2*i:2*i+2], 16, 8)
		ct3[i] = uint8(ui64)
	}

	for i := 0; i < len(ct3_tail_str)/2; i++ {
		ui64, _ := strconv.ParseUint(ct3_tail_str[2*i:2*i+2], 16, 16)
		ct3_tail[i] = uint8(ui64) // correction? Changed from uint16 to uint8
	}

	for i := len(ct3_tail_str) / 2; i < 128; i++ {
		ct3_tail[i] = uint8(0)
	}

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
	newvalues, err := tls.Get1RTT_HS_new(HS, H2, H7, pt2_len, pt2, ct3_len, ct3, ct3_tail, ct3_tail_len, H_state_tr7_32, http_msg_ciphertext)

	if err != nil {
		fmt.Println("Error in TLS Key Schedule", err)
	}

	plaintext := newvalues[0]
	cr_int := 0x0d
	lf_int := 0x0a

	cr := uint16(cr_int)
	lf := uint16(lf_int)

	log.Println("Plaintext: ", reflect.TypeOf(plaintext))
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
	log.Println("Type of plaintext: ", reflect.TypeOf(plaintext))
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
