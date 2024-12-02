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
	VoteBatchSize = 2
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

	// all of the following values compose the preimage that is hashed
	// to produce the public input needed to verify AggregatedProof.
	// they are extracted from the MerkleProofs:
	// ProcessID     --> ProcessID.Value
	// CensusRoot    --> CensusRoot.Value
	// BallotMode    --> BallotMode.Value
	// EncryptionKey --> EncryptionKey.Value
	// Nullifiers    --> Ballot[i].NewKey
	// Ballots       --> Ballot[i].NewValue
	// Addressess    --> Commitment[i].NewKey
	// Commitments   --> Commitment[i].NewValue
}

// Define declares the circuit's constraints
func (circuit Circuit) Define(api frontend.API) error {
	packedInput := circuit.packInputs(api)

	circuit.verifyAggregatedZKProof(api, packedInput)
	circuit.verifyMerkleProofs(api, poseidon.Hash)
	circuit.verifyMerkleTransitions(api)
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

func (circuit Circuit) verifyMerkleProofs(api frontend.API, hFn arbo.Hash) {
	circuit.ProcessID.VerifyProof(api, hFn, circuit.RootHashBefore)
	circuit.CensusRoot.VerifyProof(api, hFn, circuit.RootHashBefore)
	circuit.BallotMode.VerifyProof(api, hFn, circuit.RootHashBefore)
	circuit.EncryptionKey.VerifyProof(api, hFn, circuit.RootHashBefore)
}

func (circuit Circuit) verifyMerkleTransitions(api frontend.API) {
	// verify chain of tree transitions, order here is fundamental.
	root := circuit.RootHashBefore
	api.Println("tree transition starts with RootHashBefore:", prettyHex(root))
	for i := range circuit.Ballot {
		root = circuit.Ballot[i].Verify(api, root)
	}
	for i := range circuit.Commitment {
		root = circuit.Commitment[i].Verify(api, root)
	}
	root = circuit.ResultsAdd.Verify(api, root)
	api.Println("verified merkle transition ResultsAdd", circuit.ResultsAdd.OldValue, "->", circuit.ResultsAdd.NewValue)
	root = circuit.ResultsSub.Verify(api, root)
	api.Println("verified merkle transition ResultsSub", circuit.ResultsSub.OldValue, "->", circuit.ResultsSub.NewValue)
	api.Println("and now root is", prettyHex(root), "should be equal to RootHashAfter", prettyHex(circuit.RootHashAfter))
	api.AssertIsEqual(root, circuit.RootHashAfter)
}

func (circuit Circuit) verifyResults(api frontend.API) {
	sum := api.Add(0, 0)
	for i := range circuit.Ballot {
		sum = api.Add(sum, circuit.Ballot[i].NewValue)
	}
	// TODO: mock, sum should be elGamal arithmetic
	api.AssertIsEqual(api.Add(circuit.ResultsAdd.OldValue, sum),
		circuit.ResultsAdd.NewValue)
}

//	when Fnc0==0 && Fnc1==1 then it's an UPDATE operation

func isUpdate(api frontend.API, fnc0, fnc1 frontend.Variable) frontend.Variable {
	fnc0IsZero := api.IsZero(fnc0)

	// Check if fnc1 is 1 (not zero)
	fnc1IsOne := api.Sub(1, api.IsZero(fnc1))

	// Combine conditions: fnc0 == 0 AND fnc1 == 1
	return api.And(fnc0IsZero, fnc1IsOne)
}

// verifyOverwrites is not planned for PoC v1.0, but we implemented the backend anyway
func (circuit Circuit) verifyOverwrites(api frontend.API) {
	// TODO: mock, sum should be elGamal arithmetic
	sum := api.Add(0, 0)
	for i := range circuit.Ballot {
		sum = api.Add(sum, api.Select(isUpdate(api, circuit.Ballot[i].Fnc0, circuit.Ballot[i].Fnc1),
			circuit.Ballot[i].OldValue, 0))
	}
	api.AssertIsEqual(api.Add(circuit.ResultsSub.OldValue, sum),
		circuit.ResultsSub.NewValue)
}

func (circuit Circuit) verifyStats(api frontend.API) {
	// TBD
	// Check NumVotes = len(Nullifiers)
	// Check NumOverwrites = len(EncryptedBallots) - len(Nullifiers)
}
