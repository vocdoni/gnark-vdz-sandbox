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
	"hash"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
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
	if err := o.ArboState.Add([]byte{0x00}, processID); err != nil {
		return err
	}
	if err := o.ArboState.Add([]byte{0x01}, censusRoot); err != nil {
		return err
	}
	if err := o.ArboState.Add([]byte{0x02}, ballotMode); err != nil {
		return err
	}
	if err := o.ArboState.Add([]byte{0x03}, encryptionKey); err != nil {
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
	mockProof, err := o.GenMerkleProofFromArbo([]byte{0xff})
	if err != nil {
		return err
	}
	mockProofPair := MerkleProofPair{
		MerkleProof: mockProof,
		NewRootHash: []byte{0x00},
		NewLeaf:     []byte{0xff},
	}
	o.Witnesses.MerkleProofs.ResultsAdd = mockProofPair
	o.Witnesses.MerkleProofs.ResultsSub = mockProofPair
	for i := range o.Witnesses.MerkleProofs.Address {
		o.Witnesses.MerkleProofs.Address[i] = mockProofPair
	}
	for i := range o.Witnesses.MerkleProofs.Ballot {
		o.Witnesses.MerkleProofs.Ballot[i] = mockProofPair
	}
	for i := range o.Witnesses.MerkleProofs.Commitment {
		o.Witnesses.MerkleProofs.Commitment[i] = mockProofPair
	}
	for i := range o.Witnesses.MerkleProofs.Nullifier {
		o.Witnesses.MerkleProofs.Nullifier[i] = mockProofPair
	}
	return nil
}

// updateState updates the state according to transfer
// numTransfer is the number of the transfer currently handled (between 0 and BatchSizeCircuit)
func (o *Operator) updateState(t Vote) error {
	// set witnesses for the leaves

	// set witnesses for the public keys
	// o.Witnesses.PublicKeysSender.A.X = senderAccount.pubKey.A.X
	// o.Witnesses.PublicKeysSender.A.Y = senderAccount.pubKey.A.Y
	// fmt.Println("PublicKeysSender", o.Witnesses.PublicKeysSender.A.Y)

	// // set witnesses for the accounts before update
	// o.Witnesses.Process.ProcessID = senderAccount.index
	// o.Witnesses.Process.CensusRoot = senderAccount.censusRoot
	// o.Witnesses.Process.BallotMode = senderAccount.balance
	// o.Witnesses.Process.ResultsAdd = senderAccount.balance
	// o.Witnesses.Process.ResultsSub = senderAccount.balance

	//  Set witnesses for the proof of inclusion of sender and receivers account before update
	var buf bytes.Buffer
	_, err := buf.Write(o.HashState)
	if err != nil {
		return err
	}
	merkleRootBefore, proofInclusionSenderBefore, numLeaves, err := merkletree.BuildReaderProof(&buf, o.h, o.h.Size(), 0)
	if err != nil {
		return err
	}

	// verify the proof in plain go...
	merkletree.VerifyProof(o.h, merkleRootBefore, proofInclusionSenderBefore, 0, numLeaves)

	o.Witnesses.RootHashBefore = merkleRootBefore
	// o.Witnesses.MerkleProofSenderBefore.RootHash = merkleRootBefore

	// for i := 0; i < len(proofInclusionSenderBefore); i++ {
	// 	fmt.Println(len(o.Witnesses.MerkleProofSenderBefore.Path), "vs", len(proofInclusionSenderBefore))
	// 	o.Witnesses.MerkleProofSenderBefore.Path[i] = proofInclusionSenderBefore[i]
	// }

	// // set witnesses for the transfer
	// o.Witnesses.Ballots.ChoicesAdd = t.amount
	// o.Witnesses.Ballots.ChoicesSub = t.amount
	// o.Witnesses.Ballots.Signature.R.X = t.signature.R.X
	// o.Witnesses.Ballots.Signature.R.Y = t.signature.R.Y
	// o.Witnesses.Ballots.Signature.S = t.signature.S[:]

	// verifying the signature. The msg is the hash (o.h) of the transfer
	// nonce ∥ amount ∥ senderpubKey(x&y) ∥ receiverPubkey(x&y)
	resSig, err := t.Verify(o.h)
	if err != nil {
		return err
	}
	if !resSig {
		return ErrWrongSignature
	}

	// // count vote in results
	// dummy := senderAccount.balance

	// // set the witnesses for the account after update
	// o.Witnesses.Process.ProcessID = senderAccount.index
	// o.Witnesses.Process.CensusRoot = senderAccount.censusRoot
	// o.Witnesses.Process.BallotMode = senderAccount.balance
	// o.Witnesses.Results.ResultsAdd = dummy.Add(&senderAccount.balance, &t.amount)
	// o.Witnesses.Results.ResultsSub = dummy.Add(&senderAccount.balance, &t.amount)

	// // update the state of the operator
	// copy(o.State[int(posSender)*SizeAccount:], senderAccount.Serialize())
	// o.h.Reset()
	// _, _ = o.h.Write(senderAccount.Serialize())
	// bufSender := o.h.Sum([]byte{})
	// copy(o.HashState[int(posSender)*o.h.Size():(int(posSender)+1)*o.h.Size()], bufSender)

	//  Set witnesses for the proof of inclusion of sender and receivers account after update
	// buf.Reset()
	_, err = buf.Write(o.HashState)
	if err != nil {
		return err
	}
	merkleRootAfer, proofInclusionSenderAfter, _, err := merkletree.BuildReaderProof(&buf, o.h, o.h.Size(), 0)
	if err != nil {
		return err
	}
	// merkleProofHelperSenderAfter := merkle.GenerateProofHelper(proofInclusionSenderAfter, posSender, numLeaves)

	o.Witnesses.RootHashAfter = merkleRootAfer
	// o.Witnesses.MerkleProofSenderAfter.RootHash = merkleRootAfer

	for i := 0; i < len(proofInclusionSenderAfter); i++ {
		// o.Witnesses.MerkleProofSenderAfter.Path[i] = proofInclusionSenderAfter[i]
	}

	return nil
}
