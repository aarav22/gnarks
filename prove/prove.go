package main

import (
	"log"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

// x**3 + x + 5 == y
type CubicCircuit struct {
	// struct tags on a variable is optional
	// default uses variable name and secret visibility.
	X frontend.Variable `gnark:"x"`
	Y frontend.Variable `gnark:",public"`
}

// Define declares the circuit constraints
// x**3 + x + 5 == y
func (circuit *CubicCircuit) Define(api frontend.API) error {
	return nil
}

func main() {
	err := proveGroth16()
	if err != nil {
		log.Fatal("groth16 error:", err)
	}

}

func proveGroth16() error {
	// instantiate a curve-typed object
	cs := groth16.NewCS(ecc.BN254)

	// read cubic.r1cs file
	{
		f, err := os.Open("./cubic.r1cs")
		if err != nil {
			return err
		}
		_, err = cs.ReadFrom(f)
		if err != nil {
			return err
		}
		f.Close()
	}

	pk := groth16.NewProvingKey(ecc.BN254)

	// read proving key
	{
		f, err := os.Open("./cubic.g16.pk")
		if err != nil {
			return err
		}
		_, err = pk.ReadFrom(f)
		if err != nil {
			return err
		}
		f.Close()
	}

	// witness definition
	assignment := CubicCircuit{X: 2, Y: 15}
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return err
	}

	// extract the public part only
	publicWitness, err := witness.Public()
	if err != nil {
		return err
	}

	// save witness
	{
		f, err := os.Create("cubic.public.wtns")
		if err != nil {
			return err
		}

		_, err = publicWitness.WriteTo(f)
		if err != nil {
			return err
		}
	}

	// groth16: Prove
	proof, err := groth16.Prove(cs, pk, witness)
	if err != nil {
		return err
	}

	// save proof to file
	{
		f, _ := os.Create("cubic.g16.proof")
		_, _ = proof.WriteRawTo(f)
	}

	return nil
}
