## GNARKS Experimentation

This repository contains the code for the GNARKS experimentation. It is based on the [gnark](https://github.com/Consensys/gnark) library.

### Installation

#### Requirements
`
go = 1.19
`

#### Usage
I'm using go workspace to manage my projects. See here: https://github.com/golang/tools/blob/master/gopls/doc/workspace.md

cubic contains a single file that to setup, prove and verify a circuit. It is located in the gnarks folder.
to run it, simply run the following command:
```bash
go mod tidy # to fetch dependencies
go run cubic/cubic.go
```

Other modules such as `setup`, `prove`, and `verify` implement each step separately and require file transfers to work. Running them is similar to running cubic as described above.

Running `setup` should output: proving key, verification key, and a constraint system. The constraint system is a file that contains the constraints of the circuit. It is used by the prover to generate a proof.

Running `prove` should output: a proof and a public witness. The public witness is used by the verifier to verify the proof.

Running `verify` should output: true if the proof is valid, false otherwise.


