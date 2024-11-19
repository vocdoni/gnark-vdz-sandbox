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

// Queue queue for storing the transfers (fixed size queue)
type Queue struct {
	listTransfers chan Vote
}

// NewQueue creates a new queue, BatchSizeCircuit is the capacity
func NewQueue(BatchSizeCircuit int) Queue {
	resChan := make(chan Vote, BatchSizeCircuit)
	var res Queue
	res.listTransfers = resChan
	return res
}

// Operator represents a rollup operator
type Operator struct {
	State      []byte            // list of accounts: index ∥ nonce ∥ balance ∥ pubkeyX ∥ pubkeyY, each chunk is 256 bits
	HashState  []byte            // Hashed version of the state, each chunk is 256bits: ... ∥ H(index ∥ nonce ∥ balance ∥ pubkeyX ∥ pubkeyY)) ∥ ...
	AccountMap map[string]uint64 // hashmap of all available accounts (the key is the account.pubkey.X), the value is the index of the account in the state
	nbAccounts int               // number of accounts managed by this operator
	h          hash.Hash         // hash function used to build the Merkle Tree
	q          Queue             // queue of transfers
	batch      int               // current number of transactions in a batch
	Witnesses  Circuit           // witnesses for the snark circuit
	ArboState  *arbo.Tree
}

// NewOperator creates a new operator.
// nbAccounts is the number of accounts managed by this operator, h is the hash function for the merkle proofs
func NewOperator(nbAccounts int) Operator {
	res := Operator{}

	// create a list of empty accounts
	res.State = make([]byte, SizeAccount*nbAccounts)

	// initialize hash of the state
	res.HashState = make([]byte, hFunc.Size()*nbAccounts)
	for i := 0; i < nbAccounts; i++ {
		hFunc.Reset()
		_, _ = hFunc.Write(res.State[i*SizeAccount : i*SizeAccount+SizeAccount])
		s := hFunc.Sum([]byte{})
		copy(res.HashState[i*hFunc.Size():(i+1)*hFunc.Size()], s)
	}

	res.AccountMap = make(map[string]uint64)
	res.nbAccounts = nbAccounts
	res.h = hFunc
	res.q = NewQueue(BatchSize)
	res.batch = 0
	return res
}

func (o *Operator) H() hash.Hash {
	return o.h
}

// ReadAccount reads the account located at index i
func (o *Operator) ReadAccount(i uint64) (Voter, error) {
	var res Voter
	err := Deserialize(&res, o.State[int(i)*SizeAccount:int(i)*SizeAccount+SizeAccount])
	if err != nil {
		return res, err
	}
	return res, nil
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

	// mock, to avoid nulls
	o.Witnesses.NumVotes = 0
	o.Witnesses.NumOverwrites = 0
	o.Witnesses.AggregatedProof = 0
	o.Witnesses.BallotSum = 0
	o.mockProofs()

	// if o.Witnesses.MerkleProofs.ProcessID, err = o.GenMerkleProofFromArbo([]byte{0x00}); err != nil {
	// 	return err
	// }
	// if o.Witnesses.MerkleProofs.CensusRoot, err = o.GenMerkleProofFromArbo([]byte{0x01}); err != nil {
	// 	return err
	// }
	// if o.Witnesses.MerkleProofs.BallotMode, err = o.GenMerkleProofFromArbo([]byte{0x02}); err != nil {
	// 	return err
	// }
	// if o.Witnesses.MerkleProofs.EncryptionKey, err = o.GenMerkleProofFromArbo([]byte{0x03}); err != nil {
	// 	return err
	// }

	return nil
}

func (o *Operator) mockProofs() error {
	mockProof, err := o.GenMerkleProofFromArbo([]byte{0xff})
	if err != nil {
		return err
	}
	mockProofPair := MerkleProofPair{
		Root:     mockProof.Root,
		Siblings: mockProof.Siblings,
		Key:      mockProof.Key,
		Value:    mockProof.Value,
		IsOld0:   0,
		Fnc:      mockProof.Fnc,
		OldRoot:  mockProof.Root,
		OldKey:   mockProof.Key,
		OldValue: mockProof.Value,
	}
	o.Witnesses.MerkleProofs.ResultsAdd = mockProofPair
	// o.Witnesses.MerkleProofs.ResultsSub = mockProofPair
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

func toHex(v frontend.Variable) string {
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

func (o *Operator) addKey(k []byte, v []byte) (MerkleProof, MerkleProof, error) {
	fmt.Println("\nwill add key", "k=", k, "v=", v)
	mpBefore, err := o.GenMerkleProofFromArbo(k)
	if err != nil {
		return MerkleProof{}, MerkleProof{}, err
	}
	fmt.Println("before:", "root=", toHex(mpBefore.Root), "k=", mpBefore.Key, "v=", mpBefore.Value)
	for i := range mpBefore.Siblings {
		fmt.Println("siblings=", toHex(mpBefore.Siblings[i]))
	}
	if err := o.ArboState.Add(k, v); err != nil {
		return MerkleProof{}, MerkleProof{}, err
	}

	mpAfter, err := o.GenMerkleProofFromArbo(k)
	if err != nil {
		return MerkleProof{}, MerkleProof{}, err
	}
	fmt.Println("after: ", "root=", toHex(mpAfter.Root), "k=", mpAfter.Key, "v=", mpAfter.Value)
	for i := range mpAfter.Siblings {
		fmt.Println("siblings=", toHex(mpAfter.Siblings[i]))
	}

	root, _ := o.ArboState.Root()
	o.ArboState.PrintGraphviz(root)

	if _, b := os.LookupEnv("HACK"); b && bytes.Equal(k, []byte{0x04}) {
		fmt.Printf("\n ...now hack key 0x00=%v and regenerate proof for key 0x04\n", v)

		if err := o.ArboState.Update([]byte{0x00}, []byte{0xca, 0xca}); err != nil {
			return MerkleProof{}, MerkleProof{}, err
		}
		mpAfter, err := o.GenMerkleProofFromArbo(k)
		if err != nil {
			return MerkleProof{}, MerkleProof{}, err
		}
		fmt.Println("hacked:", "root=", toHex(mpAfter.Root), "k=", mpAfter.Key, "v=", mpAfter.Value)
		for i := range mpAfter.Siblings {
			fmt.Println("siblings=", toHex(mpAfter.Siblings[i]))
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

	// add key 4
	{
		root, err := o.ArboState.Root()
		if err != nil {
			return err
		}

		mpBefore, mpAfter, err := o.addKey([]byte{0x04}, []byte{0x00})
		if err != nil {
			return err
		}
		fmt.Printf("%+v\n", mpBefore)
		fmt.Printf("%+v\n", mpAfter)
		o.Witnesses.MerkleProofs.ResultsAdd, err = o.GenMerkleProofPairFromArbo([]byte{0x04})
		if err != nil {
			return err
		}
		o.Witnesses.MerkleProofs.ResultsAdd.OldRoot = arbo.BytesLEToBigInt(root)
		fmt.Printf("%+v\n", o.Witnesses.MerkleProofs.ResultsAdd)

		if mpBefore.Fnc == 1 && mpAfter.Fnc == 0 {
			o.Witnesses.MerkleProofs.ResultsAdd.Fnc = 1
		}
	}
	// // add key 5
	// {
	// 	root, err := o.ArboState.Root()
	// 	if err != nil {
	// 		return err
	// 	}

	// 	mpBefore, mpAfter, err := o.addKey([]byte{0x05}, []byte{0x00})
	// 	if err != nil {
	// 		return err
	// 	}

	// 	o.Witnesses.MerkleProofs.ResultsSub, err = o.GenMerkleProofPairFromArbo([]byte{0x05})
	// 	if err != nil {
	// 		return err
	// 	}
	// 	o.Witnesses.MerkleProofs.ResultsSub.OldRoot = arbo.BytesLEToBigInt(root)

	// 	if mpBefore.Fnc == 1 && mpAfter.Fnc == 0 {
	// 		o.Witnesses.MerkleProofs.ResultsSub.Fnc = 1
	// 	}
	// }
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
