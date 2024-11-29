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

	ballotSum *big.Int
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

	if _, _, err := addKey(tree, KeyProcessID, processID); err != nil {
		return Operator{}, err
	}
	if _, _, err := addKey(tree, KeyCensusRoot, censusRoot); err != nil {
		return Operator{}, err
	}
	if _, _, err := addKey(tree, KeyBallotMode, ballotMode); err != nil {
		return Operator{}, err
	}
	if _, _, err := addKey(tree, KeyEncryptionKey, encryptionKey); err != nil {
		return Operator{}, err
	}
	if _, _, err := addKey(tree, KeyResultsAdd, []byte{0x00}); err != nil {
		return Operator{}, err
	}
	if _, _, err := addKey(tree, KeyResultsSub, []byte{0x00}); err != nil {
		return Operator{}, err
	}

	o := Operator{
		state: tree,
	}

	o.Witnesses.NumNewVotes = 0
	o.Witnesses.NumOverwrites = 0
	o.Witnesses.AggregatedProof = 0
	o.Witnesses.BallotSum = 0
	o.ballotSum = big.NewInt(0)

	if o.Witnesses.ProcessID, err = GenMerkleProof(o.state, KeyProcessID); err != nil {
		return Operator{}, err
	}
	if o.Witnesses.CensusRoot, err = GenMerkleProof(o.state, KeyCensusRoot); err != nil {
		return Operator{}, err
	}
	if o.Witnesses.BallotMode, err = GenMerkleProof(o.state, KeyBallotMode); err != nil {
		return Operator{}, err
	}
	if o.Witnesses.EncryptionKey, err = GenMerkleProof(o.state, KeyEncryptionKey); err != nil {
		return Operator{}, err
	}

	return o, nil
}

func addKey(t *arbo.Tree, k []byte, v []byte) (ArboProof, ArboProof, error) {
	fmt.Println("\nadding key", "k=", k, "v=", v)
	mpBefore, err := GenArboProof(t, k)
	if err != nil {
		return ArboProof{}, ArboProof{}, err
	}
	fmt.Println("before:", "root=", prettyHex(mpBefore.Root), "k=", mpBefore.Key, "v=", mpBefore.Value,
		"existence=", mpBefore.Existence)
	for i := range mpBefore.Siblings {
		fmt.Println("siblings=", prettyHex(mpBefore.Siblings[i]))
	}
	if _, _, err := t.Get(k); errors.Is(err, arbo.ErrKeyNotFound) {
		if err := t.Add(k, v); err != nil {
			return ArboProof{}, ArboProof{}, fmt.Errorf("add key failed: %w", err)
		}
	} else {
		fmt.Println("\nkey exists, update instead", "k=", k, "v=", v)
		if err := t.Update(k, v); err != nil {
			return ArboProof{}, ArboProof{}, err
		}
	}

	mpAfter, err := GenArboProof(t, k)
	if err != nil {
		return ArboProof{}, ArboProof{}, err
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
			return ArboProof{}, ArboProof{}, err
		}
		mpAfter, err := GenArboProof(t, k)
		if err != nil {
			return ArboProof{}, ArboProof{}, err
		}
		fmt.Println("hacked:", "root=", prettyHex(mpAfter.Root), "k=", mpAfter.Key, "v=", mpAfter.Value)
		for i := range mpAfter.Siblings {
			fmt.Println("siblings=", prettyHex(mpAfter.Siblings[i]))
		}

	}

	return mpBefore, mpAfter, nil
}

// addVote updates the state according to transfer
// numTransfer is the number of the transfer currently handled (between 0 and BatchSizeCircuit)
func (o *Operator) addVote(t Vote) error {
	// RootHashBefore
	{
		root, err := o.state.Root()
		if err != nil {
			return err
		}
		o.Witnesses.RootHashBefore = arbo.BytesLEToBigInt(root)
	}

	o.Witnesses.BallotSum = o.ballotSum.Add(o.ballotSum, &t.ballot)

	// update key 4 (ResultsAdd)
	{
		mpBefore, mpAfter, err := addKey(o.state, []byte{0x04}, arbo.BigIntToBytesLE(32, &t.ballot))
		if err != nil {
			return err
		}
		o.Witnesses.ResultsAdd = MerkleTransitionFromArboProofPair(mpBefore, mpAfter)
	}

	// update key 5 (ResultsSub)
	{
		mpBefore, mpAfter, err := addKey(o.state, []byte{0x05}, []byte{0x00}) // mock
		if err != nil {
			return err
		}
		o.Witnesses.ResultsSub = MerkleTransitionFromArboProofPair(mpBefore, mpAfter)
	}

	// add a mock ballot
	{
		mpBefore, mpAfter, err := addKey(o.state, t.nullifier, arbo.BigIntToBytesLE(32, &t.ballot))
		if err != nil {
			return err
		}
		o.Witnesses.Ballot[0] = MerkleTransitionFromArboProofPair(mpBefore, mpAfter)
	}

	// add a mock commitment
	{
		mpBefore, mpAfter, err := addKey(o.state, t.address, arbo.BigIntToBytesLE(32, &t.commitment))
		if err != nil {
			return err
		}
		o.Witnesses.Commitment[0] = MerkleTransitionFromArboProofPair(mpBefore, mpAfter)
	}

	// RootHashAfter
	{
		root, err := o.state.Root()
		if err != nil {
			return err
		}
		o.Witnesses.RootHashAfter = arbo.BytesLEToBigInt(root)
	}

	return nil
}
