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

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/frontend"
	"go.vocdoni.io/dvote/db"
	"go.vocdoni.io/dvote/tree/arbo"
)

var hFunc = mimc.NewMiMC()

// BatchSize size of a batch of transactions to put in a snark
var BatchSize = 10

// Operator represents a rollup operator
type Operator struct {
	h         hash.Hash // hash function used to build the Merkle Tree
	Witnesses Circuit   // witnesses for the snark circuit
	ArboState *arbo.Tree
}

// NewOperator creates a new operator.
// nbAccounts is the number of accounts managed by this operator, h is the hash function for the merkle proofs
func NewOperator(nbAccounts int) Operator {
	res := Operator{}

	res.h = hFunc
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
		Database: db, MaxLevels: 4,
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
	o.Witnesses.NumVotes = 0
	o.Witnesses.NumOverwrites = 0
	o.Witnesses.AggregatedProof = 0
	o.Witnesses.BallotSum = 0
	o.mockProofs()

	if o.Witnesses.MerkleProofs.ProcessID, err = o.GenMerkleProofFromArbo([]byte{0x00}); err != nil {
		return err
	}
	if o.Witnesses.MerkleProofs.CensusRoot, err = o.GenMerkleProofFromArbo([]byte{0x01}); err != nil {
		return err
	}
	if o.Witnesses.MerkleProofs.BallotMode, err = o.GenMerkleProofFromArbo([]byte{0x02}); err != nil {
		return err
	}
	if o.Witnesses.MerkleProofs.EncryptionKey, err = o.GenMerkleProofFromArbo([]byte{0x03}); err != nil {
		return err
	}

	return nil
}

func (o *Operator) mockProofs() error {
	mockProof, err := o.GenArboProof([]byte{0xff})
	if err != nil {
		return err
	}
	mockProofPair := MerkleTransitionFromArboProofPair(mockProof, mockProof)
	o.Witnesses.MerkleProofs.ResultsAdd = mockProofPair
	o.Witnesses.MerkleProofs.ResultsSub = mockProofPair
	// for i := range o.Witnesses.MerkleProofs.Address {
	// 	o.Witnesses.MerkleProofs.Address[i] = mockProofPair
	// }
	// for i := range o.Witnesses.MerkleProofs.Ballot {
	// 	o.Witnesses.MerkleProofs.Ballot[i] = mockProofPair
	// }
	// for i := range o.Witnesses.MerkleProofs.Commitment {
	// 	o.Witnesses.MerkleProofs.Commitment[i] = mockProofPair
	// }
	// for i := range o.Witnesses.MerkleProofs.Nullifier {
	// 	o.Witnesses.MerkleProofs.Nullifier[i] = mockProofPair
	// }
	return nil
}

func prettyHex(v frontend.Variable) string {
	switch v := v.(type) {
	case (*big.Int):
		return hex.EncodeToString(arbo.BigIntToBytesLE(32, v)[:4])
	case int:
		return fmt.Sprintf("%d", v)
	case []byte:
		return fmt.Sprintf("(byte)%x", v)
	default:
		return fmt.Sprintf("(unknown)%+v", v)
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
			return ArboProof{}, ArboProof{}, err
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

	root, _ := o.ArboState.Root()
	o.ArboState.PrintGraphviz(root)

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

	o.Witnesses.ballotSum.Add(&o.Witnesses.ballotSum, &t.ballot)

	o.Witnesses.BallotSum = o.Witnesses.ballotSum

	// update key 4 (ResultsAdd)
	{
		mpBefore, mpAfter, err := o.addKey([]byte{0x04}, arbo.BigIntToBytesLE(32, &t.ballot))
		if err != nil {
			return err
		}
		fmt.Printf("%+v\n", mpBefore)
		fmt.Printf("%+v\n", mpAfter)
		o.Witnesses.MerkleProofs.ResultsAdd = MerkleTransitionFromArboProofPair(mpBefore, mpAfter)
	}

	// add key 0f (mocking a new nullifier)
	{
		mpBefore, mpAfter, err := o.addKey([]byte{0x0f}, []byte{0xff})
		if err != nil {
			return err
		}
		fmt.Printf("%+v\n", mpBefore)
		fmt.Printf("%+v\n", mpAfter)
		o.Witnesses.MerkleProofs.ResultsSub = MerkleTransitionFromArboProofPair(mpBefore, mpAfter)
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
