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
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"os"

	"go.vocdoni.io/dvote/db"
	"go.vocdoni.io/dvote/tree/arbo"
)

var hashFunc = arbo.HashFunctionPoseidon

var (
	KeyProcessID     = []byte{0x00}
	KeyCensusRoot    = []byte{0x01}
	KeyBallotMode    = []byte{0x02}
	KeyEncryptionKey = []byte{0x03}
	KeyResultsAdd    = []byte{0x04}
	KeyResultsSub    = []byte{0x05}
)

// Operator represents a rollup operator
type Operator struct {
	state     *arbo.Tree
	Witnesses Circuit // witnesses for the snark circuit

	resultsAdd     *big.Int
	resultsSub     *big.Int
	ballotSum      *big.Int
	overwriteSum   *big.Int
	ballotCount    int
	overwriteCount int
	votes          []Vote
}

// NewOperator creates a new operator.
func NewOperator(db db.Database, processID, censusRoot, ballotMode, encryptionKey []byte) (Operator, error) {
	tree, err := arbo.NewTree(arbo.Config{
		Database: db, MaxLevels: maxLevels,
		HashFunction: hashFunc,
	})
	if err != nil {
		return Operator{}, err
	}

	if err := addKey(tree, KeyProcessID, processID); err != nil {
		return Operator{}, err
	}
	if err := addKey(tree, KeyCensusRoot, censusRoot); err != nil {
		return Operator{}, err
	}
	if err := addKey(tree, KeyBallotMode, ballotMode); err != nil {
		return Operator{}, err
	}
	if err := addKey(tree, KeyEncryptionKey, encryptionKey); err != nil {
		return Operator{}, err
	}
	if err := addKey(tree, KeyResultsAdd, []byte{0x00}); err != nil {
		return Operator{}, err
	}
	if err := addKey(tree, KeyResultsSub, []byte{0x00}); err != nil {
		return Operator{}, err
	}

	o := Operator{
		state: tree,
	}

	if err := o.StartBatch(); err != nil {
		return Operator{}, err
	}

	return o, nil
}

func (o *Operator) StartBatch() error {
	o.Witnesses.NumNewVotes = 0
	o.Witnesses.NumOverwrites = 0
	o.Witnesses.AggregatedProof = 0
	if o.resultsAdd == nil {
		o.resultsAdd = big.NewInt(0)
	}
	if o.resultsSub == nil {
		o.resultsSub = big.NewInt(0)
	}
	o.ballotSum = big.NewInt(0)
	o.overwriteSum = big.NewInt(0)
	o.ballotCount = 0
	o.overwriteCount = 0
	o.votes = []Vote{}

	var err error
	if o.Witnesses.ProcessID, err = GenMerkleProof(o.state, KeyProcessID); err != nil {
		return err
	}
	if o.Witnesses.CensusRoot, err = GenMerkleProof(o.state, KeyCensusRoot); err != nil {
		return err
	}
	if o.Witnesses.BallotMode, err = GenMerkleProof(o.state, KeyBallotMode); err != nil {
		return err
	}
	if o.Witnesses.EncryptionKey, err = GenMerkleProof(o.state, KeyEncryptionKey); err != nil {
		return err
	}
	return nil
}

func addKey(t *arbo.Tree, k []byte, v []byte) error {
	_, err := addKeyWithProof(t, k, v)
	return err
}

func addKeyWithProof(t *arbo.Tree, k []byte, v []byte) (MerkleTransition, error) {
	fmt.Println("\nadding key", "k=", k, "v=", v)
	mpBefore, err := GenArboProof(t, k)
	if err != nil {
		return MerkleTransition{}, err
	}
	fmt.Println("before:", "root=", prettyHex(mpBefore.Root), "k=", mpBefore.Key, "v=", mpBefore.Value,
		"existence=", mpBefore.Existence)
	for i := range mpBefore.Siblings {
		fmt.Println("siblings=", prettyHex(mpBefore.Siblings[i]))
	}
	if _, _, err := t.Get(k); errors.Is(err, arbo.ErrKeyNotFound) {
		if err := t.Add(k, v); err != nil {
			return MerkleTransition{}, fmt.Errorf("add key failed: %w", err)
		}
	} else {
		fmt.Println("key exists, update instead")
		if err := t.Update(k, v); err != nil {
			return MerkleTransition{}, fmt.Errorf("update key failed: %w", err)
		}
	}

	mpAfter, err := GenArboProof(t, k)
	if err != nil {
		return MerkleTransition{}, err
	}
	fmt.Println("after: ", "root=", prettyHex(mpAfter.Root), "k=", mpAfter.Key, "v=", mpAfter.Value)
	for i := range mpAfter.Siblings {
		fmt.Println("siblings=", prettyHex(mpAfter.Siblings[i]))
	}

	// root, _ := o.ArboState.Root()
	// o.ArboState.PrintGraphviz(root)

	if _, b := os.LookupEnv("HACK"); b && bytes.Equal(k, []byte{0x03}) {
		fmt.Printf("\n ...now hack key 0x00=%v and regenerate proof for key 0x04\n", v)

		if err := t.Update([]byte{0x00}, []byte{0xca, 0xca}); err != nil {
			return MerkleTransition{}, err
		}
		mpAfter, err := GenArboProof(t, k)
		if err != nil {
			return MerkleTransition{}, err
		}
		fmt.Println("hacked:", "root=", prettyHex(mpAfter.Root), "k=", mpAfter.Key, "v=", mpAfter.Value)
		for i := range mpAfter.Siblings {
			fmt.Println("siblings=", prettyHex(mpAfter.Siblings[i]))
		}

	}

	return MerkleTransitionFromArboProofPair(mpBefore, mpAfter), nil
}

// AddVote adds a vote to the state
//   - if nullifier exists, it counts as vote overwrite
//
// TODO: use Tx to rollback in case of failure
func (o *Operator) AddVote(v Vote) error {
	if len(o.votes) >= VoteBatchSize {
		return fmt.Errorf("too many votes for this batch")
	}
	if _, v, err := o.state.Get(v.nullifier); err == nil {
		// if nullifier existed, it's a vote overwrite, need to count the overwritten vote as ResultsSub
		o.overwriteSum = o.overwriteSum.Add(
			o.overwriteSum, arbo.BytesLEToBigInt(v))
		o.overwriteCount++
	}

	o.ballotSum = o.ballotSum.Add(o.ballotSum, &v.ballot)
	o.ballotCount++
	o.votes = append(o.votes, v)
	return nil
}

func (o *Operator) EndBatch() error {
	// now build ordered chain of MerkleTransitions
	var err error

	// RootHashBefore
	o.Witnesses.RootHashBefore, err = o.RootAsBigInt()
	if err != nil {
		return err
	}

	// add Ballots
	for i := range o.votes {
		o.Witnesses.Ballot[i], err = addKeyWithProof(o.state,
			o.votes[i].nullifier, arbo.BigIntToBytesLE(32, &o.votes[i].ballot))
		if err != nil {
			return err
		}
	}

	// add Commitments
	for i := range o.votes {
		o.Witnesses.Commitment[i], err = addKeyWithProof(o.state,
			o.votes[i].address, arbo.BigIntToBytesLE(32, &o.votes[i].commitment))
		if err != nil {
			return err
		}
	}

	// update ResultsAdd
	o.Witnesses.ResultsAdd, err = addKeyWithProof(o.state,
		KeyResultsAdd, arbo.BigIntToBytesLE(32, o.resultsAdd.Add(o.resultsAdd, o.ballotSum)))
	if err != nil {
		return err
	}

	// update ResultsSub
	o.Witnesses.ResultsSub, err = addKeyWithProof(o.state,
		KeyResultsSub, arbo.BigIntToBytesLE(32, o.resultsSub.Add(o.resultsSub, o.overwriteSum)))
	if err != nil {
		return err
	}

	// update stats
	o.Witnesses.NumNewVotes = o.ballotCount
	o.Witnesses.NumOverwrites = o.overwriteCount

	// RootHashAfter
	o.Witnesses.RootHashAfter, err = o.RootAsBigInt()
	if err != nil {
		return err
	}

	return nil
}

func (o *Operator) RootAsBigInt() (*big.Int, error) {
	root, err := o.state.Root()
	if err != nil {
		return nil, err
	}
	return arbo.BytesLEToBigInt(root), nil
}
