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
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
)

const (
	nbAccounts       = 16 // 16 accounts so we know that the proof length is 5
	depth            = 5  // size fo the inclusion proofs
	BatchSizeCircuit = 1  // nbTranfers to batch in a proof
)

// Circuit "toy" rollup circuit where an operator can generate a proof that he processed
// some transactions
type Circuit struct {
	// ---------------------------------------------------------------------------------------------
	// SECRET INPUTS

	// list of accounts involved before update and their public keys
	SenderAccountsBefore   [BatchSizeCircuit]ProcessConstraints
	ReceiverAccountsBefore [BatchSizeCircuit]ProcessConstraints
	PublicKeysSender       [BatchSizeCircuit]eddsa.PublicKey

	// list of accounts involved after update and their public keys
	SenderAccountsAfter   [BatchSizeCircuit]ProcessConstraints
	ReceiverAccountsAfter [BatchSizeCircuit]ProcessConstraints
	PublicKeysReceiver    [BatchSizeCircuit]eddsa.PublicKey

	// list of transactions
	Transfers [BatchSizeCircuit]VoteConstraints

	// list of proofs corresponding to sender and receiver accounts
	MerkleProofReceiverBefore [BatchSizeCircuit]merkle.MerkleProof
	MerkleProofReceiverAfter  [BatchSizeCircuit]merkle.MerkleProof
	MerkleProofSenderBefore   [BatchSizeCircuit]merkle.MerkleProof
	MerkleProofSenderAfter    [BatchSizeCircuit]merkle.MerkleProof
	LeafReceiver              [BatchSizeCircuit]frontend.Variable
	LeafSender                [BatchSizeCircuit]frontend.Variable

	// ---------------------------------------------------------------------------------------------
	// PUBLIC INPUTS

	// list of root hashes
	RootHashesBefore [BatchSizeCircuit]frontend.Variable `gnark:",public"`
	RootHashesAfter  [BatchSizeCircuit]frontend.Variable `gnark:",public"`
}

// ProcessConstraints represents the process encoded as constraints
type ProcessConstraints struct {
	ProcessID     frontend.Variable
	CensusRoot    frontend.Variable
	BallotMode    frontend.Variable
	EncryptionKey eddsa.PublicKey `gnark:"-"`
}

// VoteConstraints represents a vote encoded as constraints
type VoteConstraints struct {
	Amount         frontend.Variable
	Nonce          frontend.Variable `gnark:"-"`
	SenderPubKey   eddsa.PublicKey   `gnark:"-"`
	ReceiverPubKey eddsa.PublicKey   `gnark:"-"`
	Signature      eddsa.Signature
}

func (circuit *Circuit) postInit(api frontend.API) error {
	for i := 0; i < BatchSizeCircuit; i++ {

		// setting the sender accounts before update
		circuit.SenderAccountsBefore[i].EncryptionKey = circuit.PublicKeysSender[i]

		// setting the sender accounts after update
		circuit.SenderAccountsAfter[i].EncryptionKey = circuit.PublicKeysSender[i]

		// setting the receiver accounts before update
		circuit.ReceiverAccountsBefore[i].EncryptionKey = circuit.PublicKeysReceiver[i]

		// setting the receiver accounts after update
		circuit.ReceiverAccountsAfter[i].EncryptionKey = circuit.PublicKeysReceiver[i]

		// setting the transfers
		circuit.Transfers[i].Nonce = circuit.SenderAccountsBefore[i].CensusRoot
		circuit.Transfers[i].SenderPubKey = circuit.PublicKeysSender[i]
		circuit.Transfers[i].ReceiverPubKey = circuit.PublicKeysReceiver[i]

		// allocate the slices for the Merkle proofs
		// circuit.allocateSlicesMerkleProofs()

	}
	return nil
}

func (circuit *Circuit) allocateSlicesMerkleProofs() {
	for i := 0; i < BatchSizeCircuit; i++ {
		// allocating slice for the Merkle paths
		circuit.MerkleProofReceiverBefore[i].Path = make([]frontend.Variable, depth)
		circuit.MerkleProofReceiverAfter[i].Path = make([]frontend.Variable, depth)
		circuit.MerkleProofSenderBefore[i].Path = make([]frontend.Variable, depth)
		circuit.MerkleProofSenderAfter[i].Path = make([]frontend.Variable, depth)
	}
}

// Define declares the circuit's constraints
func (circuit Circuit) Define(api frontend.API) error {
	if err := circuit.postInit(api); err != nil {
		return err
	}
	// hash function for the merkle proof and the eddsa signature
	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// verifications of:
	// - Merkle proofs of the accounts
	// - the signatures
	// - accounts' balance consistency
	for i := 0; i < BatchSizeCircuit; i++ {

		// the root hashes of the Merkle path must match the public ones given in the circuit
		api.AssertIsEqual(circuit.RootHashesBefore[i], circuit.MerkleProofReceiverBefore[i].RootHash)
		api.AssertIsEqual(circuit.RootHashesBefore[i], circuit.MerkleProofSenderBefore[i].RootHash)
		api.AssertIsEqual(circuit.RootHashesAfter[i], circuit.MerkleProofReceiverAfter[i].RootHash)
		api.AssertIsEqual(circuit.RootHashesAfter[i], circuit.MerkleProofSenderAfter[i].RootHash)

		// the leafs of the Merkle proofs must match the index of the accounts
		api.AssertIsEqual(circuit.ReceiverAccountsBefore[i].ProcessID, circuit.LeafReceiver[i])
		api.AssertIsEqual(circuit.ReceiverAccountsAfter[i].ProcessID, circuit.LeafReceiver[i])
		api.AssertIsEqual(circuit.SenderAccountsBefore[i].ProcessID, circuit.LeafSender[i])
		api.AssertIsEqual(circuit.SenderAccountsAfter[i].ProcessID, circuit.LeafSender[i])

		// verify the inclusion proofs
		circuit.MerkleProofReceiverBefore[i].VerifyProof(api, &hFunc, circuit.LeafReceiver[i])
		circuit.MerkleProofSenderBefore[i].VerifyProof(api, &hFunc, circuit.LeafSender[i])
		circuit.MerkleProofReceiverAfter[i].VerifyProof(api, &hFunc, circuit.LeafReceiver[i])
		circuit.MerkleProofSenderAfter[i].VerifyProof(api, &hFunc, circuit.LeafSender[i])

		// verify the transaction transfer
		err := verifyTransferSignature(api, circuit.Transfers[i], hFunc)
		if err != nil {
			return err
		}

		// update the accounts
		verifyAccountUpdated(api, circuit.SenderAccountsBefore[i], circuit.ReceiverAccountsBefore[i], circuit.SenderAccountsAfter[i], circuit.ReceiverAccountsAfter[i], circuit.Transfers[i].Amount)
	}

	return nil
}

// verifyTransferSignature ensures that the signature of the transfer is valid
func verifyTransferSignature(api frontend.API, t VoteConstraints, hFunc mimc.MiMC) error {
	// Reset the hash state!
	hFunc.Reset()

	// the signature is on h(nonce ∥ amount ∥ senderpubKey (x&y) ∥ receiverPubkey(x&y))
	hFunc.Write(t.Nonce, t.Amount, t.SenderPubKey.A.X, t.SenderPubKey.A.Y, t.ReceiverPubKey.A.X, t.ReceiverPubKey.A.Y)
	htransfer := hFunc.Sum()

	curve, err := twistededwards.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}

	hFunc.Reset()
	err = eddsa.Verify(curve, t.Signature, htransfer, t.SenderPubKey, &hFunc)
	if err != nil {
		return err
	}
	return nil
}

func verifyAccountUpdated(api frontend.API, from, to, fromUpdated, toUpdated ProcessConstraints, amount frontend.Variable) {
	// ensure that nonce is correctly updated
	nonceUpdated := api.Add(from.CensusRoot, 1)
	api.AssertIsEqual(nonceUpdated, fromUpdated.CensusRoot)
	api.AssertIsEqual(to.CensusRoot, toUpdated.CensusRoot)

	// ensures that the amount is less than the balance
	api.AssertIsLessOrEqual(amount, from.BallotMode)

	// ensure that balance is correctly updated
	fromBalanceUpdated := api.Sub(from.BallotMode, amount)
	api.AssertIsEqual(fromBalanceUpdated, fromUpdated.BallotMode)

	toBalanceUpdated := api.Add(to.BallotMode, amount)
	api.AssertIsEqual(toBalanceUpdated, toUpdated.BallotMode)
}
