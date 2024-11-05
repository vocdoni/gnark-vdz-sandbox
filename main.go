package main

import (
	"gnark-vdz/rollup"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/consensys/gnark/std/signature/eddsa"
	"github.com/consensys/gnark/test"
)

func main() {
	// compiles our circuit into a R1CS
	var circuit rollup.Circuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}
	// groth16 zkSNARK: Setup
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}

	// witness definition
	assignment := rollup.Circuit{
		SenderAccountsBefore:      [1]rollup.AccountConstraints{},
		ReceiverAccountsBefore:    [1]rollup.AccountConstraints{},
		PublicKeysSender:          [1]eddsa.PublicKey{},
		SenderAccountsAfter:       [1]rollup.AccountConstraints{},
		ReceiverAccountsAfter:     [1]rollup.AccountConstraints{},
		PublicKeysReceiver:        [1]eddsa.PublicKey{},
		Transfers:                 [1]rollup.TransferConstraints{},
		MerkleProofReceiverBefore: [1]merkle.MerkleProof{},
		MerkleProofReceiverAfter:  [1]merkle.MerkleProof{},
		MerkleProofSenderBefore:   [1]merkle.MerkleProof{},
		MerkleProofSenderAfter:    [1]merkle.MerkleProof{},
		LeafReceiver:              [1]frontend.Variable{},
		LeafSender:                [1]frontend.Variable{},
		RootHashesBefore:          [1]frontend.Variable{},
		RootHashesAfter:           [1]frontend.Variable{},
	}
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}

	if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err != nil {
		panic(err)
	}

	// groth16: Prove & Verify
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		panic(err)
	}

	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		panic(err)
	}
}
