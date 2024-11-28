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
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"os"
	"reflect"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/frontend"
	"go.vocdoni.io/dvote/db"
	"go.vocdoni.io/dvote/tree/arbo"
)

var hFunc = mimc.NewMiMC()

// Operator represents a rollup operator
type Operator struct {
	h         hash.Hash // hash function used to build the Merkle Tree
	Witnesses Circuit   // witnesses for the snark circuit
	ArboState *arbo.Tree

	ballotSum *big.Int
}

// NewOperator creates a new operator.
// nbAccounts is the number of accounts managed by this operator, h is the hash function for the merkle proofs
func NewOperator() Operator {
	res := Operator{}

	res.h = hFunc
	res.ballotSum = big.NewInt(0)
	return res
}

func (o *Operator) H() hash.Hash {
	return o.h
}

func (o *Operator) UpdateState(t Vote) error {
	return o.updateState(t)
}

func (o *Operator) initState(db db.Database, processID, censusRoot, ballotMode, encryptionKey []byte) error {
	tree, err := arbo.NewTree(arbo.Config{
		Database: db, MaxLevels: maxLevels,
		HashFunction: arbo.HashFunctionPoseidon,
	})
	if err != nil {
		return err
	}
	o.ArboState = tree
	if _, _, err := o.addKey([]byte{0x00}, processID); err != nil {
		return err
	}
	if _, _, err := o.addKey([]byte{0x01}, censusRoot); err != nil {
		return err
	}
	if _, _, err := o.addKey([]byte{0x02}, ballotMode); err != nil {
		return err
	}
	if _, _, err := o.addKey([]byte{0x03}, encryptionKey); err != nil {
		return err
	}
	if _, _, err := o.addKey([]byte{0x04}, []byte{0x00}); err != nil { // ResultsAdd
		return err
	}
	if _, _, err := o.addKey([]byte{0x05}, []byte{0x00}); err != nil { // ResultsSub
		return err
	}

	// mock, to avoid nulls
	o.Witnesses.NumNewVotes = 0
	o.Witnesses.NumOverwrites = 0
	o.Witnesses.AggregatedProof = 0
	o.Witnesses.BallotSum = 0

	if o.Witnesses.ProcessID, err = o.GenMerkleProofFromArbo([]byte{0x00}); err != nil {
		return err
	}
	if o.Witnesses.CensusRoot, err = o.GenMerkleProofFromArbo([]byte{0x01}); err != nil {
		return err
	}
	if o.Witnesses.BallotMode, err = o.GenMerkleProofFromArbo([]byte{0x02}); err != nil {
		return err
	}
	if o.Witnesses.EncryptionKey, err = o.GenMerkleProofFromArbo([]byte{0x03}); err != nil {
		return err
	}

	return nil
}

func prettyHex(v frontend.Variable) string {
	type hasher interface {
		HashCode() [16]byte
	}
	switch v := v.(type) {
	case (*big.Int):
		return hex.EncodeToString(arbo.BigIntToBytesLE(32, v)[:4])
	case int:
		return fmt.Sprintf("%d", v)
	case []byte:
		return fmt.Sprintf("%x", v[:4])
	case hasher:
		return fmt.Sprintf("%x", v.HashCode())
	default:
		return fmt.Sprintf("(%v)=%+v", reflect.TypeOf(v), v)
	}
}

func (o *Operator) addKey(k []byte, v []byte) (ArboProof, ArboProof, error) {
	fmt.Println("\nwill add key", "k=", k, "v=", v)
	mpBefore, err := o.GenArboProof(k)
	if err != nil {
		return ArboProof{}, ArboProof{}, err
	}
	fmt.Println("before:", "root=", prettyHex(mpBefore.Root), "k=", mpBefore.Key, "v=", mpBefore.Value,
		"existence=", mpBefore.Existence)
	for i := range mpBefore.Siblings {
		fmt.Println("siblings=", prettyHex(mpBefore.Siblings[i]))
	}
	if _, _, err := o.ArboState.Get(k); errors.Is(err, arbo.ErrKeyNotFound) {
		if err := o.ArboState.Add(k, v); err != nil {
			return ArboProof{}, ArboProof{}, fmt.Errorf("add key failed: %w", err)
		}
	} else {
		fmt.Println("\nkey exists, update instead", "k=", k, "v=", v)
		if err := o.ArboState.Update(k, v); err != nil {
			return ArboProof{}, ArboProof{}, err
		}
	}

	mpAfter, err := o.GenArboProof(k)
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

		if err := o.ArboState.Update([]byte{0x00}, []byte{0xca, 0xca}); err != nil {
			return ArboProof{}, ArboProof{}, err
		}
		mpAfter, err := o.GenArboProof(k)
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

// updateState updates the state according to transfer
// numTransfer is the number of the transfer currently handled (between 0 and BatchSizeCircuit)
func (o *Operator) updateState(t Vote) error {
	// RootHashBefore
	{
		root, err := o.ArboState.Root()
		if err != nil {
			return err
		}
		o.Witnesses.RootHashBefore = arbo.BytesLEToBigInt(root)
	}

	o.Witnesses.BallotSum = o.ballotSum.Add(o.ballotSum, &t.ballot)

	// update key 4 (ResultsAdd)
	{
		mpBefore, mpAfter, err := o.addKey([]byte{0x04}, arbo.BigIntToBytesLE(32, &t.ballot))
		if err != nil {
			return err
		}
		o.Witnesses.ResultsAdd = MerkleTransitionFromArboProofPair(mpBefore, mpAfter)
	}

	// update key 5 (ResultsSub)
	{
		mpBefore, mpAfter, err := o.addKey([]byte{0x05}, []byte{0x00}) // mock
		if err != nil {
			return err
		}
		o.Witnesses.ResultsSub = MerkleTransitionFromArboProofPair(mpBefore, mpAfter)
	}

	// add a mock ballot
	{
		mpBefore, mpAfter, err := o.addKey(t.nullifier, arbo.BigIntToBytesLE(32, &t.ballot))
		if err != nil {
			return err
		}
		o.Witnesses.Ballot[0] = MerkleTransitionFromArboProofPair(mpBefore, mpAfter)
	}

	// add a mock commitment
	{
		mpBefore, mpAfter, err := o.addKey(t.address, arbo.BigIntToBytesLE(32, &t.commitment))
		if err != nil {
			return err
		}
		o.Witnesses.Commitment[0] = MerkleTransitionFromArboProofPair(mpBefore, mpAfter)
	}

	// RootHashAfter
	{
		root, err := o.ArboState.Root()
		if err != nil {
			return err
		}
		o.Witnesses.RootHashAfter = arbo.BytesLEToBigInt(root)
	}

	return nil
}
