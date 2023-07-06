package main

import (
	"log"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
)

func main() {
	vk := groth16.NewVerifyingKey(ecc.BN254)

	// read the verification key from file
	{
		f, err := os.Open("cubic.g16.vk")
		if err != nil {
			log.Fatal(err)
		}
		_, err = vk.ReadFrom(f)
		if err != nil {
			log.Fatal(err)
		}
		f.Close()
	}

	proof := groth16.NewProof(ecc.BN254)

	// read the proof from file
	{
		f, err := os.Open("cubic.g16.proof")
		if err != nil {
			log.Fatal(err)
		}
		_, err = proof.ReadFrom(f)
		if err != nil {
			log.Fatal(err)
		}
		f.Close()
	}

	witness, _ := witness.New(ecc.BN254.ScalarField())

	// read the witness from file
	{
		f, err := os.Open("cubic.public.wtns")
		if err != nil {
			log.Fatal(err)
		}
		_, err = witness.ReadFrom(f)
		if err != nil {
			log.Fatal(err)
		}
		f.Close()
	}

	// verify the proof
	if err := groth16.Verify(proof, vk, witness); err != nil {
		log.Fatal("invalid proof")
	}

}
