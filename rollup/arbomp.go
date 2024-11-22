package rollup

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	garbo "github.com/vocdoni/gnark-crypto-primitives/arbo"
	"github.com/vocdoni/gnark-crypto-primitives/poseidon"
	"github.com/vocdoni/gnark-crypto-primitives/smt"
	"go.vocdoni.io/dvote/tree/arbo"
)

// MerkleProof stores the leaf, the path, and the root hash.
type MerkleProof struct {
	// Key+Value hashed through Siblings path, should produce Root hash
	Root     frontend.Variable
	Siblings [depth]frontend.Variable
	Key      frontend.Variable
	Value    frontend.Variable

	IsOld0 frontend.Variable
	Fnc    frontend.Variable // 0: inclusion, 1: non inclusion
}

// MerkleProofPair stores a pair of leaves and root hashes, and a single path common to both proofs
type MerkleProofPair struct {
	// Key+Value hashed through Siblings path, should produce Root hash
	Root     frontend.Variable
	Siblings [depth]frontend.Variable
	Key      frontend.Variable
	Value    frontend.Variable

	IsOld0 frontend.Variable
	Fnc    frontend.Variable // 0: inclusion, 1: non inclusion
	// OldKey+OldValue hashed through same Siblings should produce OldRoot hash
	OldRoot  frontend.Variable
	OldKey   frontend.Variable
	OldValue frontend.Variable
	OldFnc   frontend.Variable
}

// GenMerkleProofPairFromArbo generates a MerkleProof for a given key
// in the Tree
func (o *Operator) GenMerkleProofPairFromArbo(k []byte) (MerkleProofPair, error) {
	kAux, v, siblings, existence, err := o.ArboState.GenProof(k)
	if err != nil {
		return MerkleProofPair{}, err
	}
	fmt.Println("existence?", existence, kAux, v)

	var cp MerkleProofPair
	root, err := o.ArboState.Root()
	if err != nil {
		return MerkleProofPair{}, err
	}
	cp.Root = arbo.BytesLEToBigInt(root)
	unpackedSiblings, err := arbo.UnpackSiblings(arbo.HashFunctionPoseidon, siblings)
	if err != nil {
		return MerkleProofPair{}, err
	}
	cp.Siblings = padSiblings(unpackedSiblings)
	if !existence {
		cp.OldKey = arbo.BytesLEToBigInt(kAux)
		cp.OldValue = arbo.BytesLEToBigInt(v)
	} else {
		cp.OldKey = frontend.Variable(0)
		cp.OldValue = frontend.Variable(0)
	}
	cp.Key = arbo.BytesLEToBigInt(k)
	cp.Value = arbo.BytesLEToBigInt(v)
	if existence {
		cp.Fnc = 0 // inclusion
	} else {
		cp.Fnc = 1 // non inclusion
	}

	cp.IsOld0 = 0
	if !existence && bytes.Equal(kAux, []byte{0x00}) && bytes.Equal(v, []byte{0x00}) {
		cp.IsOld0 = 1
	}

	cp.OldFnc = 0

	return cp, nil
}

func (o *Operator) GenMerkleProofFromArbo(k []byte) (MerkleProof, error) {
	root, err := o.ArboState.Root()
	if err != nil {
		return MerkleProof{}, err
	}
	leafK, leafV, siblings, exists, err := o.ArboState.GenProof(k)
	if err != nil {
		return MerkleProof{}, err
	}
	return NewMerkleProofFromArbo(root, leafK, leafV, siblings, exists)
}

func NewMerkleProofFromArbo(root, leafK, leafV, packedSiblings []byte, exists bool) (MerkleProof, error) {
	unpackedSiblings, err := arbo.UnpackSiblings(arbo.HashFunctionPoseidon, packedSiblings)
	if err != nil {
		return MerkleProof{}, err
	}
	fmt.Println("existence?", exists, leafK, leafV)

	fnc := int(0) // inclusion
	if !exists {
		fnc = 1 // non-inclusion
	}

	isOld0 := 0
	if !exists && bytes.Equal(leafK, []byte{}) && bytes.Equal(leafV, []byte{}) {
		isOld0 = 1
	}

	return MerkleProof{
		Root:     arbo.BytesLEToBigInt(root),
		Siblings: padSiblings(unpackedSiblings),

		Key:   arbo.BytesLEToBigInt(leafK),
		Value: arbo.BytesLEToBigInt(leafV),

		Fnc:    fnc,
		IsOld0: isOld0,
	}, nil
}

func padSiblings(unpackedSiblings [][]byte) [depth]frontend.Variable {
	paddedSiblings := [depth]frontend.Variable{}
	for i := range depth {
		if i < len(unpackedSiblings) {
			paddedSiblings[i] = arbo.BytesLEToBigInt(unpackedSiblings[i])
		} else {
			paddedSiblings[i] = big.NewInt(0)
		}
	}
	return paddedSiblings
}

// VerifyProof takes a Merkle root, a proofSet, and a proofIndex and returns
// true if the first element of the proof set is a leaf of data in the Merkle
// root. False is returned if the proof set or Merkle root is nil, and if
// 'numLeaves' equals 0.
func (mp *MerkleProof) VerifyProof(api frontend.API, h garbo.Hash) {
	garbo.CheckInclusionProof(api, h, mp.Key, mp.Value, mp.Root, mp.Siblings[:])
}

func (mp *MerkleProofPair) VerifyProof(api frontend.API, h garbo.Hash) {
	garbo.CheckInclusionProof(api, h, mp.Key, mp.Value, mp.Root, mp.Siblings[:])
}

// VerifyProof takes a Merkle root, a proofSet, and a proofIndex and returns
// true if the first element of the proof set is a leaf of data in the Merkle
// root. False is returned if the proof set or Merkle root is nil, and if
// 'numLeaves' equals 0.
func (mp *MerkleProofPair) VerifyProofPair(api frontend.API, h garbo.Hash) {
	if mp.OldFnc == 1 && mp.Fnc == 0 {
		api.Println("pair of proofs is adding a leaf, should first check exclusion and then inclusion")
	}
	if mp.OldFnc == 0 && mp.Fnc == 0 {
		api.Println("pair of proofs is updating a leaf, should check both inclusions")
	}
	if mp.OldFnc == 0 && mp.Fnc == 1 {
		api.Println("pair of proofs is removing a leaf, should check inclusion and then exclusion")
	}
	api.Println("key, value, root", mp.Key, mp.Value, toHex(mp.Root), mp.Fnc)
	api.Println("oky, ovlue, orot", mp.OldKey, mp.OldValue, toHex(mp.OldRoot), mp.OldFnc)
	for i := range mp.Siblings {
		api.Println("sib", toHex(mp.Siblings[i]))
	}
	// garbo.CheckInclusionProof(api, h, mp.Key, mp.Value, mp.Root, mp.Siblings[:])

	// garbo.CheckAdditionProof(api,
	// 	poseidon.Hash,
	// 	mp.Key,
	// 	mp.Value,
	// 	mp.Root,
	// 	mp.OldKey,
	// 	mp.OldValue,
	// 	mp.OldRoot,
	// 	mp.Siblings[:])

	smt.Processor(api,
		mp.OldRoot,
		mp.Siblings[:],
		mp.OldKey,
		mp.OldValue,
		mp.IsOld0,
		mp.Key,
		mp.Value,
		mp.OldFnc,
		mp.Fnc,
	)

	api.Println("proved transition")

	// } else {
	// 	api.Println("pair of proofs is an update, first check old value")
	// 	smt.VerifierFull(api,
	// 		mp.OldRoot,
	// 		mp.Key,
	// 		mp.Value,
	// 		0,
	// 		mp.OldKey,
	// 		mp.OldValue,
	// 		0,
	// 		mp.Siblings[:])
	// }
	api.Println("x key root", mp.Key, mp.Root)
	api.Println("x oky orot", mp.OldKey, mp.OldRoot)
}

// TODO: use arbo.Hash
type arboHash *poseidon.Poseidon
