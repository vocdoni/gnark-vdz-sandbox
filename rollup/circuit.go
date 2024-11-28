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
	"github.com/vocdoni/gnark-crypto-primitives/arbo"
	"github.com/vocdoni/gnark-crypto-primitives/poseidon"
)

const (
	// size of the inclusion proofs
	maxLevels = 16
	// maxKeyLen is ceil(maxLevels/8)
	maxKeyLen = (maxLevels + 7) / 8
	// nbVotes that were processed in AggregatedProof
	VoteBatchSize = 1
)

type Circuit struct {
	// ---------------------------------------------------------------------------------------------
	// PUBLIC INPUTS

	// list of root hashes
	RootHashBefore frontend.Variable `gnark:",public"`
	RootHashAfter  frontend.Variable `gnark:",public"`
	NumNewVotes    frontend.Variable `gnark:",public"`
	NumOverwrites  frontend.Variable `gnark:",public"`

	// ---------------------------------------------------------------------------------------------
	// SECRET INPUTS

	AggregatedProof frontend.Variable // mock, this should be a zkProof

	ProcessID     MerkleProof
	CensusRoot    MerkleProof
	BallotMode    MerkleProof
	EncryptionKey MerkleProof
	ResultsAdd    MerkleTransition
	ResultsSub    MerkleTransition
	Ballot        [VoteBatchSize]MerkleTransition
	Commitment    [VoteBatchSize]MerkleTransition

	// all of these values compose the preimage that is hashed
	// to produce the public input needed to verify AggregatedProof.
	// they are extracted from the MerkleProofs,
	// except BallotSum, so we declare it as a frontend.Variable
	// ProcessID     --> ProcessID.Value
	// CensusRoot    --> CensusRoot.Value
	// BallotMode    --> BallotMode.Value
	// EncryptionKey --> EncryptionKey.Value
	// Nullifiers    --> Ballot[i].NewKey
	// Ballots       --> Ballot[i].NewValue
	// Addressess    --> Commitment[i].NewKey
	// Commitments   --> Commitment[i].NewValue
	BallotSum frontend.Variable
}

// Define declares the circuit's constraints
func (circuit Circuit) Define(api frontend.API) error {
	packedInput := circuit.packInputs(api)

	circuit.verifyAggregatedZKProof(api, packedInput)
	circuit.verifyMerkleProofs(api, poseidon.Hash)
	circuit.verifyMerkleTransitions(api, poseidon.Hash)
	circuit.verifyResults(api)
	circuit.verifyOverwrites(api)
	circuit.verifyStats(api)

	return nil
}

// packInputs extracts the Values (or NewKey, NewValue) of
//
//	circuit.ProcessID,
//	circuit.CensusRoot,
//	circuit.BallotMode,
//	circuit.EncryptionKey,
//	circuit.Commitment[],
//	circuit.Ballot[],
//
// and returns a hash that is used to verify AggregatedZKProof
func (circuit Circuit) packInputs(api frontend.API) frontend.Variable {
	for i, p := range []MerkleProof{
		circuit.ProcessID,
		circuit.CensusRoot,
		circuit.BallotMode,
		circuit.EncryptionKey,
	} {
		api.Println("packInputs mock", i, p.Value) // mock
	}
	for i := range circuit.Ballot {
		api.Println("packInputs mock nullifier", i, circuit.Ballot[i].NewKey) // mock
		api.Println("packInputs mock ballot", i, circuit.Ballot[i].NewValue)  // mock
	}
	for i := range circuit.Commitment {
		api.Println("packInputs mock address", i, circuit.Commitment[i].NewKey)      // mock
		api.Println("packInputs mock commitment", i, circuit.Commitment[i].NewValue) // mock
	}
	return 1
}

func (circuit Circuit) verifyAggregatedZKProof(api frontend.API, packedInput frontend.Variable) {
	api.Println("verifyAggregatedZKProof mock", circuit.AggregatedProof, packedInput) // mock

	api.AssertIsEqual(1, 1) // TODO: mock, should actually verify Aggregated ZKProof
}

func (circuit Circuit) verifyMerkleProofs(api frontend.API, hFunc arbo.Hash) {
	// check process is untouched
	verifyMerkleProof(api, hFunc, circuit.RootHashBefore, circuit.ProcessID)
	verifyMerkleProof(api, hFunc, circuit.RootHashBefore, circuit.CensusRoot)
	verifyMerkleProof(api, hFunc, circuit.RootHashBefore, circuit.BallotMode)
	verifyMerkleProof(api, hFunc, circuit.RootHashBefore, circuit.EncryptionKey)
}

func (circuit Circuit) verifyMerkleTransitions(api frontend.API, hFunc arbo.Hash) {
	// verify key transitions, order here is fundamental.
	root := circuit.RootHashBefore
	api.Println("root starts with RootHashBefore, i.e.", prettyHex(root))
	root = verifyMerkleTransition(api, hFunc, root, circuit.ResultsAdd)
	root = verifyMerkleTransition(api, hFunc, root, circuit.ResultsSub)
	for i := range circuit.Ballot {
		root = verifyMerkleTransition(api, hFunc, root, circuit.Ballot[i])
	}
	for i := range circuit.Commitment {
		root = verifyMerkleTransition(api, hFunc, root, circuit.Commitment[i])
	}
	api.Println("and now root is", prettyHex(root), "should be equal to RootHashAfter", prettyHex(circuit.RootHashAfter))
	api.AssertIsEqual(root, circuit.RootHashAfter)
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
	api.Println("now root is", prettyHex(oldRoot))
	api.AssertIsEqual(oldRoot, mp.OldRoot)
	mp.Verify(api, hFunc)
	return mp.NewRoot
}

func (circuit Circuit) verifyResults(api frontend.API) {
	// TODO: mock, sum should be elGamal arithmetic
	api.AssertIsEqual(api.Add(circuit.ResultsAdd.OldValue, circuit.BallotSum),
		circuit.ResultsAdd.NewValue)
}

// verifyOverwrites is not planned for PoC v1.0
func (circuit Circuit) verifyOverwrites(api frontend.API) {
	// TODO: mock, sum should be elGamal arithmetic
	// api.AssertIsEqual(api.Add(circuit.ResultsSub.OldValue, circuit.BallotSum),
	// 	circuit.ResultsSub.NewValue)
}

func (circuit Circuit) verifyStats(api frontend.API) {
	// TBD
	// Check NumVotes = len(Nullifiers)
	// Check NumOverwrites = len(EncryptedBallots) - len(Nullifiers)
}
