package main

import (
	"log"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
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
	x3 := api.Mul(circuit.X, circuit.X, circuit.X)
	api.AssertIsEqual(circuit.Y, api.Add(x3, circuit.X, 5))
	return nil
}

func main() {
	err := generateGroth16()
	if err != nil {
		log.Fatal("groth16 error:", err)
	}
}

func generateGroth16() error {
	var circuit CubicCircuit

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return err
	}

	// save r1cs to file
	{
		f, err := os.Create("cubic.r1cs")
		if err != nil {
			return err
		}
		_, err = r1cs.WriteTo(f)
		if err != nil {
			return err
		}
	}

	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		return err
	}
	{
		f, err := os.Create("cubic.g16.vk")
		if err != nil {
			return err
		}
		_, err = vk.WriteRawTo(f)
		if err != nil {
			return err
		}
	}
	{
		f, err := os.Create("cubic.g16.pk")
		if err != nil {
			return err
		}
		_, err = pk.WriteRawTo(f)
		if err != nil {
			return err
		}
	}
	return nil
}
