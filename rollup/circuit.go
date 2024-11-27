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
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/vocdoni/gnark-crypto-primitives/arbo"
	"github.com/vocdoni/gnark-crypto-primitives/poseidon"
)

const (
	nbVoters      = 16 // 16 accounts so we know that the proof length is 5
	depth         = 5  // size fo the inclusion proofs
	VoteBatchSize = 10 // nbVotes that were processed in AggregatedProof
)

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
	ballotSum big.Int
}

// MerkleProofs contains the SMT Witness
type MerkleProofs struct {
	ProcessID     MerkleProof
	CensusRoot    MerkleProof
	BallotMode    MerkleProof
	EncryptionKey MerkleProof
	ResultsAdd    MerkleTransition
	ResultsSub    MerkleTransition
	// Nullifier     [VoteBatchSize]MerkleTransition
	// Commitment    [VoteBatchSize]MerkleTransition
	// Address       [VoteBatchSize]MerkleTransition
	// Ballot        [VoteBatchSize]MerkleTransition
}

// Define declares the circuit's constraints
func (circuit Circuit) Define(api frontend.API) error {
	packedInput := packInputs(
		api,
	// circuit.MerkleProofs.ProcessID,
	// circuit.MerkleProofs.CensusRoot,
	// circuit.MerkleProofs.BallotMode,
	// circuit.MerkleProofs.EncryptionKey,
	// circuit.MerkleProofs.Nullifiers,
	// circuit.MerkleProofs.Commitments,
	// circuit.MerkleProofs.Addresses,
	// circuit.MerkleProofs.EncryptedBallots,
	)

	verifyAggregatedZKProof(api, circuit.AggregatedProof, packedInput)
	verifyMerkleProofs(api, poseidon.Hash,
		circuit.RootHashBefore,
		circuit.RootHashAfter,
		circuit.MerkleProofs)
	verifyResults(api, circuit.BallotSum,
		circuit.MerkleProofs.ResultsAdd.OldValue, circuit.MerkleProofs.ResultsAdd.NewValue,
	)
	// verifyOverwrites(api, circuit.MerkleProofs.Ballot,
	// 	circuit.MerkleProofs.ResultsSub.OldValue, circuit.MerkleProofs.ResultsSub.Value,
	// )
	verifyStats(api)

	return nil
}

func packInputs(api frontend.API, mps ...MerkleProof) frontend.Variable {
	for i := range mps {
		api.Println("packInputs mock", i) // mock
	}
	return 1
}

func verifyAggregatedZKProof(api frontend.API, aggrProof, packedInput frontend.Variable) {
	api.Println("verifyAggregatedZKProof mock", aggrProof, packedInput) // mock

	api.AssertIsEqual(1, 1) // TODO: mock, should actually verify Aggregated ZKProof
}

func verifyMerkleProofs(api frontend.API, hFunc arbo.Hash, rootBefore, rootAfter frontend.Variable, mps MerkleProofs) {
	// check process is untouched
	verifyMerkleProof(api, hFunc, rootBefore, mps.ProcessID)
	verifyMerkleProof(api, hFunc, rootBefore, mps.CensusRoot)
	verifyMerkleProof(api, hFunc, rootBefore, mps.BallotMode)
	verifyMerkleProof(api, hFunc, rootBefore, mps.EncryptionKey)
	// verify key transitions, order here is fundamental.
	root := rootBefore
	api.Println("root is rootBefore, i.e.", prettyHex(root))
	root = verifyMerkleTransition(api, hFunc, root, mps.ResultsAdd)
	api.Println("now root is", prettyHex(root))
	root = verifyMerkleTransition(api, hFunc, root, mps.ResultsSub)
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
	api.Println("and now root is", prettyHex(root), "should be equal to rootAfter", prettyHex(root))
	api.AssertIsEqual(root, rootAfter)
}

func verifyMerkleProof(api frontend.API, hFunc arbo.Hash, root frontend.Variable, mp MerkleProof) {
	api.AssertIsEqual(root, mp.Root)
	mp.VerifyProof(api, hFunc)
}

// verifyMerkleTransition asserts a MerkleTransition is valid
//   - mp.OldRoot matches passed oldRoot
//   - mp.OldKey belongs to mp.OldRoot
//   - mp.NewKey belongs to mp.NewRoot
//
// and returns mp.NewRoot
func verifyMerkleTransition(api frontend.API, hFunc arbo.Hash, oldRoot frontend.Variable, mp MerkleTransition) frontend.Variable {
	api.Println("will verify merkle transition from root", prettyHex(mp.OldRoot), "->", prettyHex(mp.NewRoot))
	api.AssertIsEqual(oldRoot, mp.OldRoot)
	mp.Verify(api, hFunc)
	return mp.NewRoot
}

func verifyResults(api frontend.API, sum, resultsAddBefore, resultsAddAfter frontend.Variable,
) {
	// TODO: mock, sum should be elGamal arithmetic
	api.AssertIsEqual(api.Add(resultsAddBefore, sum), resultsAddAfter)
}

// verifyOverwrites is not planned for PoC v1.0
func verifyOverwrites(api frontend.API, ballots [VoteBatchSize]MerkleTransition, resultsSubBefore, resultsSubAfter frontend.Variable,
) {
	// TODO: mock, sum should be elGamal arithmetic
	// api.AssertIsEqual(api.Add(resultsSubBefore, ballots), resultsSubAfter)
}

func verifyStats(api frontend.API) {
	// TBD
	// Check NumVotes = len(Nullifiers)
	// Check NumOverwrites = len(EncryptedBallots) - len(Nullifiers)
}
