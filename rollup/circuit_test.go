/*
Copyright © 2020 ConsenSys

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package rollup

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/test"
)

type circuitSignature Circuit

// Circuit implements part of the rollup circuit only by declaring a subset of the constraints
func (t *circuitSignature) Define(api frontend.API) error {
	if err := (*Circuit)(t).postInit(api); err != nil {
		return err
	}
	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	return verifyVoteSignature(api, t.Votes[0], hFunc)
}

func TestCircuitSignature(t *testing.T) {
	const nbAccounts = 10

	operator, users := createOperator(nbAccounts)

	// read accounts involved in the transfer
	sender, err := operator.readAccount(0)
	if err != nil {
		t.Fatal(err)
	}

	receiver, err := operator.readAccount(1)
	if err != nil {
		t.Fatal(err)
	}

	// create the transfer and sign it
	amount := uint64(10)
	transfer := NewVote(amount, sender.pubKey, receiver.pubKey, sender.nonce)

	// sign the transfer
	_, err = transfer.Sign(users[0], operator.h)
	if err != nil {
		t.Fatal(err)
	}

	// update the state from the received transfer
	err = operator.updateState(transfer, 0)
	if err != nil {
		t.Fatal(err)
	}

	// verifies the signature of the transfer
	assert := test.NewAssert(t)

	var signatureCircuit circuitSignature
	for i := 0; i < BatchSizeCircuit; i++ {
		signatureCircuit.MerkleProofSenderBefore[i].Path = make([]frontend.Variable, depth)
		signatureCircuit.MerkleProofSenderAfter[i].Path = make([]frontend.Variable, depth)
	}

	assert.ProverSucceeded(&signatureCircuit, &operator.witnesses, test.WithCurves(ecc.BN254), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))
}

type circuitInclusionProof Circuit

func (t *circuitInclusionProof) Define(api frontend.API) error {
	hashFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	t.MerkleProofSenderBefore[0].VerifyProof(api, &hashFunc, t.LeafSender[0])
	t.MerkleProofSenderAfter[0].VerifyProof(api, &hashFunc, t.LeafSender[0])

	return nil
}

func TestCircuitInclusionProof(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping rollup tests for circleCI")
	}

	operator, users := createOperator(nbAccounts)

	// read accounts involved in the transfer
	sender, err := operator.readAccount(0)
	if err != nil {
		t.Fatal(err)
	}

	receiver, err := operator.readAccount(1)
	if err != nil {
		t.Fatal(err)
	}

	// create the transfer and sign it
	amount := uint64(16)
	transfer := NewVote(amount, sender.pubKey, receiver.pubKey, sender.nonce)

	// sign the transfer
	_, err = transfer.Sign(users[0], operator.h)
	if err != nil {
		t.Fatal(err)
	}

	// update the state from the received transfer
	err = operator.updateState(transfer, 0)
	if err != nil {
		t.Fatal(err)
	}

	// verifies the proofs of inclusion of the transfer
	assert := test.NewAssert(t)

	// we allocate the slices of the circuit before compiling it
	var inclusionProofCircuit circuitInclusionProof
	for i := 0; i < BatchSizeCircuit; i++ {
		inclusionProofCircuit.MerkleProofSenderBefore[i].Path = make([]frontend.Variable, depth)
		inclusionProofCircuit.MerkleProofSenderAfter[i].Path = make([]frontend.Variable, depth)
	}

	assert.ProverSucceeded(
		&inclusionProofCircuit,
		&operator.witnesses,
		test.WithCurves(ecc.BN254),
		test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()),
		test.WithBackends(backend.GROTH16))
}

type circuitUpdateAccount Circuit

// Circuit implements part of the rollup circuit only by declaring a subset of the constraints
func (t *circuitUpdateAccount) Define(api frontend.API) error {
	if err := (*Circuit)(t).postInit(api); err != nil {
		return err
	}

	verifyProcessUpdate(api, t.ProcessBefore[0], t.ProcessAfter[0],
		t.Votes[0].ChoicesAdd, t.Votes[0].ChoicesSub)
	return nil
}

func TestCircuitUpdateAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping rollup tests for circleCI")
	}

	operator, users := createOperator(nbAccounts)

	// read accounts involved in the transfer
	sender, err := operator.readAccount(0)
	if err != nil {
		t.Fatal(err)
	}

	receiver, err := operator.readAccount(1)
	if err != nil {
		t.Fatal(err)
	}

	// create the transfer and sign it
	amount := uint64(10)
	transfer := NewVote(amount, sender.pubKey, receiver.pubKey, sender.nonce)

	// sign the transfer
	_, err = transfer.Sign(users[0], operator.h)
	if err != nil {
		t.Fatal(err)
	}

	// update the state from the received transfer
	err = operator.updateState(transfer, 0)
	if err != nil {
		t.Fatal(err)
	}

	assert := test.NewAssert(t)

	var updateAccountCircuit circuitUpdateAccount
	(*Circuit)(&updateAccountCircuit).allocateSlicesMerkleProofs()

	assert.ProverSucceeded(&updateAccountCircuit, &operator.witnesses, test.WithCurves(ecc.BN254), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))
}

func TestCircuitFull(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping rollup tests for circleCI")
	}

	operator, users := createOperator(nbAccounts)

	// read accounts involved in the transfer
	sender, err := operator.readAccount(0)
	if err != nil {
		t.Fatal(err)
	}

	receiver, err := operator.readAccount(1)
	if err != nil {
		t.Fatal(err)
	}

	// create the transfer and sign it
	amount := uint64(10)
	transfer := NewVote(amount, sender.pubKey, receiver.pubKey, sender.nonce)

	// sign the transfer
	_, err = transfer.Sign(users[0], operator.h)
	if err != nil {
		t.Fatal(err)
	}

	// update the state from the received transfer
	err = operator.updateState(transfer, 0)
	if err != nil {
		t.Fatal(err)
	}

	assert := test.NewAssert(t)
	// verifies the proofs of inclusion of the transfer

	var rollupCircuit Circuit
	for i := 0; i < BatchSizeCircuit; i++ {
		rollupCircuit.MerkleProofSenderBefore[i].Path = make([]frontend.Variable, depth)
		rollupCircuit.MerkleProofSenderAfter[i].Path = make([]frontend.Variable, depth)
	}

	// TODO full circuit has some unconstrained inputs, that's odd.
	assert.ProverSucceeded(
		&rollupCircuit,
		&operator.witnesses,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16))
}

func TestCircuitCompile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping rollup tests for circleCI")
	}

	operator, users := createOperator(nbAccounts)

	// read accounts involved in the transfer
	sender, err := operator.readAccount(0)
	if err != nil {
		t.Fatal(err)
	}

	receiver, err := operator.readAccount(1)
	if err != nil {
		t.Fatal(err)
	}

	// create the transfer and sign it
	amount := uint64(16)
	transfer := NewVote(amount, sender.pubKey, receiver.pubKey, sender.nonce)

	// sign the transfer
	_, err = transfer.Sign(users[0], operator.h)
	if err != nil {
		t.Fatal(err)
	}

	// update the state from the received transfer
	err = operator.updateState(transfer, 0)
	if err != nil {
		t.Fatal(err)
	}

	// we allocate the slices of the circuit before compiling it
	var inclusionProofCircuit Circuit
	for i := 0; i < BatchSizeCircuit; i++ {
		inclusionProofCircuit.MerkleProofSenderBefore[i].Path = make([]frontend.Variable, depth)
		inclusionProofCircuit.MerkleProofSenderAfter[i].Path = make([]frontend.Variable, depth)
	}
	p := profile.Start()

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &inclusionProofCircuit)
	if err != nil {
		panic(err)
	}
	p.Stop()
	fmt.Println("constraints", p.NbConstraints())

	// groth16 zkSNARK: Setup
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}

	witness, err := frontend.NewWitness(operator.Witnesses(), ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}

	// if err := test.IsSolved(circuit, op.Witnesses(), ecc.BN254.ScalarField()); err != nil {
	// 	panic(err)
	// }

	// groth16: Prove & Verify
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		panic(err)
	}

	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		panic(err)
	}
}
