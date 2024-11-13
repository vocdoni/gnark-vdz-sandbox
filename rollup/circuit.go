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
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
)

const (
	nbAccounts       = 16 // 16 accounts so we know that the proof length is 5
	depth            = 5  // size fo the inclusion proofs
	BatchSizeCircuit = 1  // nbTransitions to batch in a proof
	VoteBatchSize    = 10 // nbVotes that were processed in AggregatedProof
)

// Circuit "toy" rollup circuit where an operator can generate a proof that he processed
// some transactions
type Circuit struct {
	// ---------------------------------------------------------------------------------------------
	// PUBLIC INPUTS

	// list of root hashes
	RootHashBefore [BatchSizeCircuit]frontend.Variable `gnark:",public"`
	RootHashAfter  [BatchSizeCircuit]frontend.Variable `gnark:",public"`
	NumVotes       [BatchSizeCircuit]frontend.Variable `gnark:",public"`
	NumOverwrites  [BatchSizeCircuit]frontend.Variable `gnark:",public"`

	// ---------------------------------------------------------------------------------------------
	// SECRET INPUTS

	AggregatedProof [BatchSizeCircuit]frontend.Variable // mock, this should be a zkProof
	// list of proofs corresponding to each tree modification
	MerkleProofs [BatchSizeCircuit]MerkleProofs

	// the following inputs will be used inside the circuit for some checks,
	// but also hashed to produce the public input needed to verify AggregatedProof
	// TODO: Actually all of these are also on the Leaf's inside MerkleProofs, dedup?
	Process   [BatchSizeCircuit]ProcessConstraints
	Results   [BatchSizeCircuit]ResultsConstraints
	Ballots   [BatchSizeCircuit]BallotsConstraints
	BallotSum [BatchSizeCircuit]frontend.Variable
}

// ProcessConstraints represents the process encoded as constraints
type ProcessConstraints struct {
	ProcessID     frontend.Variable
	CensusRoot    frontend.Variable
	BallotMode    frontend.Variable
	EncryptionKey eddsa.PublicKey `gnark:"-"`
}

// ResultsConstraints represents the process results, encoded as constraints
type ResultsConstraints struct {
	ResultsAdd frontend.Variable
	ResultsSub frontend.Variable
}

// BallotsConstraints represents the ballots, encoded as constraints
type BallotsConstraints struct {
	Nullifiers  [VoteBatchSize]frontend.Variable
	Commitments [VoteBatchSize]frontend.Variable
	Addressess  [VoteBatchSize]frontend.Variable
	Ballots     [VoteBatchSize]frontend.Variable
}

// MerkleProofs contains the SMT Witness
type MerkleProofs struct {
	ProcessID     MerkleProof
	CensusRoot    MerkleProof
	BallotMode    MerkleProof
	EncryptionKey MerkleProof
	ResultsAdd    MerkleProofPair
	ResultsSub    MerkleProofPair
	Nullifier     [VoteBatchSize]MerkleProofPair
	Commitment    [VoteBatchSize]MerkleProofPair
	Address       [VoteBatchSize]MerkleProofPair
	Ballot        [VoteBatchSize]MerkleProofPair
}

func (circuit *Circuit) PostInit(api frontend.API) error {
	for i := 0; i < BatchSizeCircuit; i++ {
		// allocate the slices for the Merkle proofs
		// circuit.allocateSlicesMerkleProofs()
	}
	return nil
}

func (circuit *Circuit) allocateSlicesMerkleProofs() {
	for i := range BatchSizeCircuit {
		circuit.MerkleProofs[i].ProcessID.Path = make([]frontend.Variable, depth)
		circuit.MerkleProofs[i].CensusRoot.Path = make([]frontend.Variable, depth)
		circuit.MerkleProofs[i].BallotMode.Path = make([]frontend.Variable, depth)
		circuit.MerkleProofs[i].EncryptionKey.Path = make([]frontend.Variable, depth)
		circuit.MerkleProofs[i].ResultsAdd.Path = make([]frontend.Variable, depth)
		circuit.MerkleProofs[i].ResultsSub.Path = make([]frontend.Variable, depth)
		for j := range VoteBatchSize {
			circuit.MerkleProofs[i].Address[j].Path = make([]frontend.Variable, depth)
			circuit.MerkleProofs[i].Nullifier[j].Path = make([]frontend.Variable, depth)
			circuit.MerkleProofs[i].Commitment[j].Path = make([]frontend.Variable, depth)
			circuit.MerkleProofs[i].Ballot[j].Path = make([]frontend.Variable, depth)
		}
	}
}

// Define declares the circuit's constraints
func (circuit Circuit) Define(api frontend.API) error {
	if err := circuit.PostInit(api); err != nil {
		return err
	}
	// hash function for the merkle proof and the eddsa signature
	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	for i := range BatchSizeCircuit {
		verifyAggregatedZKProof(api)
		verifyMerkleProofs(api, &hFunc,
			circuit.RootHashBefore[i],
			circuit.RootHashAfter[i],
			circuit.MerkleProofs[i])
		verifyResults(api, circuit.BallotSum[i],
			circuit.MerkleProofs[i].ResultsAdd.Leaf, circuit.MerkleProofs[i].ResultsAdd.NewLeaf,
			circuit.MerkleProofs[i].ResultsSub.Leaf, circuit.MerkleProofs[i].ResultsSub.NewLeaf,
		)
		verifyStats(api)
	}

	return nil
}

func verifyAggregatedZKProof(api frontend.API) {
	api.AssertIsBoolean(true) // TODO: mock, should actually verify Aggregated ZKProof
	return
}

func verifyMerkleProofs(api frontend.API, hFunc hash.FieldHasher, rootBefore, rootAfter frontend.Variable, mps MerkleProofs) {
	// check process is untouched
	verifyMerkleProof(api, hFunc, rootBefore, mps.ProcessID)
	verifyMerkleProof(api, hFunc, rootBefore, mps.CensusRoot)
	verifyMerkleProof(api, hFunc, rootBefore, mps.BallotMode)
	verifyMerkleProof(api, hFunc, rootBefore, mps.EncryptionKey)
	// verify key transitions, order here is fundamental.
	root := rootBefore
	root = verifyMerkleTransition(api, hFunc, root, mps.ResultsAdd)
	root = verifyMerkleTransition(api, hFunc, root, mps.ResultsSub)
	for i := range mps.Nullifier {
		root = verifyMerkleTransition(api, hFunc, root, mps.Nullifier[i])
	}
	for i := range mps.Commitment {
		root = verifyMerkleTransition(api, hFunc, root, mps.Commitment[i])
	}
	for i := range mps.Address {
		root = verifyMerkleTransition(api, hFunc, root, mps.Address[i])
	}
	for i := range mps.Ballot {
		root = verifyMerkleTransition(api, hFunc, root, mps.Ballot[i])
	}
	api.AssertIsEqual(root, rootAfter)
}

func verifyMerkleProof(api frontend.API, hFunc hash.FieldHasher, root frontend.Variable, mp MerkleProof) {
	api.AssertIsEqual(root, mp.RootHash)
	mp.VerifyProof(api, hFunc)
}

// verifyMerkleTransition checks that:
//   - mpBefore matches root
//   - mpBefore and mpAfter have equal paths (indicating rest of the tree is untouched)
//   - mpBefore and mpAfter are valid proofs
func verifyMerkleTransition(api frontend.API, hFunc hash.FieldHasher, root frontend.Variable, mp MerkleProofPair) frontend.Variable {
	api.AssertIsEqual(root, mp.RootHash)
	mp.VerifyProofPair(api, hFunc)
	return mp.NewRootHash
}

func verifyResults(api frontend.API, sum,
	resultsAddBefore, resultsAddAfter,
	resultsSubBefore, resultsSubAfter frontend.Variable,
) {
	// TODO: mock, sum should certainly not be added to both resultsAdd and resultsSub
	api.AssertIsEqual(api.Add(resultsAddBefore, sum), resultsAddAfter)
	api.AssertIsEqual(api.Add(resultsSubBefore, sum), resultsSubAfter)
}

func verifyStats(api frontend.API) {
	// TBD
	// Check NumVotes = len(Nullifiers)
	// Check NumOverwrites = len(EncryptedBallots) - len(Nullifiers)
}
