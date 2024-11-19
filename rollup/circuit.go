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
	"github.com/vocdoni/gnark-crypto-primitives/poseidon"
)

const (
	nbAccounts    = 16 // 16 accounts so we know that the proof length is 5
	depth         = 5  // size fo the inclusion proofs
	VoteBatchSize = 10 // nbVotes that were processed in AggregatedProof
)

// Circuit "toy" rollup circuit where an operator can generate a proof that he processed
// some transactions
type Circuit struct {
	// ---------------------------------------------------------------------------------------------
	// PUBLIC INPUTS

	// list of root hashes
	RootHashBefore frontend.Variable `gnark:",public"`
	RootHashAfter  frontend.Variable `gnark:",public"`
	NumVotes       frontend.Variable `gnark:",public"`
	NumOverwrites  frontend.Variable `gnark:",public"`

	// ---------------------------------------------------------------------------------------------
	// SECRET INPUTS

	AggregatedProof frontend.Variable // mock, this should be a zkProof
	// list of proofs corresponding to each tree modification
	MerkleProofs MerkleProofs

	// all of these values compose the preimage that is hashed
	// to produce the public input needed to verify AggregatedProof.
	// they are extracted from the MerkleProofs,
	// except BallotSum, so we declare it as a frontend.Variable
	// ProcessID     frontend.Variable --> MerkleProofs.ProcessID.Leaf
	// CensusRoot    frontend.Variable --> MerkleProofs.CensusRoot.Leaf
	// BallotMode    frontend.Variable --> MerkleProofs.BallotMode.Leaf
	// EncryptionKey eddsa.PublicKey `gnark:"-"` --> MerkleProofs.EncryptionKey.Leaf
	// Nullifiers    [VoteBatchSize]frontend.Variable --> MerkleProofs.Nullifier[i].Leaf
	// Commitments   [VoteBatchSize]frontend.Variable --> MerkleProofs.Commitment[i].Leaf
	// Addressess    [VoteBatchSize]frontend.Variable --> MerkleProofs.Addresse[i].Leaf
	// Ballots       [VoteBatchSize]frontend.Variable --> MerkleProofs.Ballot[i].Leaf
	BallotSum frontend.Variable
}

// MerkleProofs contains the SMT Witness
type MerkleProofs struct {
	// ProcessID     MerkleProof
	// CensusRoot    MerkleProof
	// BallotMode    MerkleProof
	// EncryptionKey MerkleProof
	ResultsAdd MerkleProofPair
	// ResultsSub MerkleProofPair
	// Nullifier     [VoteBatchSize]MerkleProofPair
	// Commitment    [VoteBatchSize]MerkleProofPair
	// Address       [VoteBatchSize]MerkleProofPair
	// Ballot        [VoteBatchSize]MerkleProofPair
}

func (circuit *Circuit) PostInit(api frontend.API) error {
	// allocate the slices for the Merkle proofs
	// circuit.allocateSlicesMerkleProofs()
	return nil
}

func (circuit *Circuit) allocateSlicesMerkleProofs() {
	// // TODO: is this needed? if depth is a const
	// circuit.MerkleProofs.ProcessID.Siblings = make([]frontend.Variable, depth)
	// circuit.MerkleProofs.CensusRoot.Siblings = make([]frontend.Variable, depth)
	// circuit.MerkleProofs.BallotMode.Siblings = make([]frontend.Variable, depth)
	// circuit.MerkleProofs.EncryptionKey.Siblings = make([]frontend.Variable, depth)
	// circuit.MerkleProofs.ResultsAdd.Siblings = make([]frontend.Variable, depth)
	// circuit.MerkleProofs.ResultsSub.Siblings = make([]frontend.Variable, depth)
	//
	//	for j := range VoteBatchSize {
	//		circuit.MerkleProofs.Address[j].Siblings = make([]frontend.Variable, depth)
	//		circuit.MerkleProofs.Nullifier[j].Siblings = make([]frontend.Variable, depth)
	//		circuit.MerkleProofs.Commitment[j].Siblings = make([]frontend.Variable, depth)
	//		circuit.MerkleProofs.Ballot[j].Siblings = make([]frontend.Variable, depth)
	//	}
}

// Define declares the circuit's constraints
func (circuit Circuit) Define(api frontend.API) error {
	if err := circuit.PostInit(api); err != nil {
		return err
	}
	// hash function for the merkle proof and the eddsa signature
	hFunc := poseidon.NewPoseidon(api)

	verifyAggregatedZKProof(api)
	verifyMerkleProofs(api, &hFunc,
		circuit.RootHashBefore,
		circuit.RootHashAfter,
		circuit.MerkleProofs)
	verifyResults(api, circuit.BallotSum,
		circuit.MerkleProofs.ResultsAdd.OldValue, circuit.MerkleProofs.ResultsAdd.Value,
	)
	// verifyOverwrites(api, circuit.MerkleProofs.Ballot,
	// 	circuit.MerkleProofs.ResultsSub.OldValue, circuit.MerkleProofs.ResultsSub.Value,
	// )
	verifyStats(api)

	return nil
}

func verifyAggregatedZKProof(api frontend.API) {
	api.AssertIsEqual(1, 1) // TODO: mock, should actually verify Aggregated ZKProof
}

func verifyMerkleProofs(api frontend.API, hFunc arboHash, rootBefore, rootAfter frontend.Variable, mps MerkleProofs) {
	// check process is untouched
	// verifyMerkleProof(api, hFunc, rootBefore, mps.ProcessID)
	// verifyMerkleProof(api, hFunc, rootBefore, mps.CensusRoot)
	// verifyMerkleProof(api, hFunc, rootBefore, mps.BallotMode)
	// verifyMerkleProof(api, hFunc, rootBefore, mps.EncryptionKey)
	// verify key transitions, order here is fundamental.
	root := rootBefore
	api.Println("root is rootBefore, i.e.", root, "=", toHex(root))
	root = verifyMerkleTransition(api, hFunc, root, mps.ResultsAdd)
	// api.Println("now root is", root, "=", toHex(root))
	// root = verifyMerkleTransition(api, hFunc, root, mps.ResultsSub)
	api.Println("and now root is", root, "=", toHex(root), "should be equal to rootAfter", toHex(root))
	// for i := range mps.Nullifier {
	// 	root = verifyMerkleTransition(api, hFunc, root, mps.Nullifier[i])
	// }
	// for i := range mps.Commitment {
	// 	root = verifyMerkleTransition(api, hFunc, root, mps.Commitment[i])
	// }
	// for i := range mps.Address {
	// 	root = verifyMerkleTransition(api, hFunc, root, mps.Address[i])
	// }
	// for i := range mps.Ballot {
	// 	root = verifyMerkleTransition(api, hFunc, root, mps.Ballot[i])
	// }
	api.AssertIsEqual(root, rootAfter)
}

func verifyMerkleProof(api frontend.API, hFunc arboHash, root frontend.Variable, mp MerkleProof) {
	api.AssertIsEqual(root, mp.Root)
	mp.VerifyProof(api, hFunc)
}

// verifyMerkleTransition asserts a MerkleProofPair is valid
//   - mp.RootHash matches passed root
//   - mp.Leaf belongs to mp.RootHash
//   - mp.NewLeaf belongs to mp.NewRootHash
//
// and returns mp.NewRootHash
func verifyMerkleTransition(api frontend.API, hFunc arboHash, root frontend.Variable, mp MerkleProofPair) frontend.Variable {
	api.AssertIsEqual(root, mp.OldRoot)
	mp.VerifyProofPair(api, hFunc)
	return mp.Root
}

func verifyResults(api frontend.API, sum, resultsAddBefore, resultsAddAfter frontend.Variable,
) {
	// TODO: mock, sum should be elGamal arithmetic
	api.AssertIsEqual(api.Add(resultsAddBefore, sum), resultsAddAfter)
}

// verifyOverwrites is not planned for PoC v1.0
func verifyOverwrites(api frontend.API, ballots [VoteBatchSize]MerkleProofPair, resultsSubBefore, resultsSubAfter frontend.Variable,
) {
	// TODO: mock, sum should be elGamal arithmetic
	// api.AssertIsEqual(api.Add(resultsSubBefore, ballots), resultsSubAfter)
}

func verifyStats(api frontend.API) {
	// TBD
	// Check NumVotes = len(Nullifiers)
	// Check NumOverwrites = len(EncryptedBallots) - len(Nullifiers)
}
