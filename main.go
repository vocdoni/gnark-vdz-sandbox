package main

import (
	"math/big"

	"gnark-vdz/rollup"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/test"
)

type simplerCircuit rollup.Circuit

const BatchSizeCircuit = 1 // nbTranfers to batch in a proof

// Circuit implements part of the rollup circuit only by declaring a subset of the constraints
func (circuit simplerCircuit) Define(api frontend.API) error {
	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	for i := 0; i < BatchSizeCircuit; i++ {
		api.AssertIsEqual(circuit.RootHashesBefore[i], circuit.MerkleProofSenderBefore[i].RootHash)
		api.AssertIsEqual(circuit.RootHashesAfter[i], circuit.MerkleProofSenderAfter[i].RootHash)
		// circuit.MerkleProofReceiverBefore[i].VerifyProof(api, &hFunc, circuit.LeafReceiver[i])
		// circuit.MerkleProofReceiverAfter[i].VerifyProof(api, &hFunc, circuit.LeafReceiver[i])
		hFunc.Write(big.NewInt(int64(1)))
		api.Println(hFunc.Sum())
	}
	return nil
}

func main() {
	// compiles our circuit into a R1CS
	var circuit simplerCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}
	// groth16 zkSNARK: Setup
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}
	op := rollup.NewOperator(10)

	witness, err := frontend.NewWitness(op.Witnesses(), ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}

	if err := test.IsSolved(circuit, op.Witnesses(), ecc.BN254.ScalarField()); err != nil {
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
