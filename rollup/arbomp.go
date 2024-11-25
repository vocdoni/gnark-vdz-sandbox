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

// ArboProof stores the proof in arbo native types
type ArboProof struct {
	// Key+Value hashed through Siblings path, should produce Root hash
	Root      []byte
	Siblings  [][]byte
	Key       []byte
	Value     []byte
	Existence bool
}

// MerkleProof stores the leaf, the path, and the root hash.
type MerkleProof struct {
	// Key+Value hashed through Siblings path, should produce Root hash
	Root     frontend.Variable
	Siblings [depth]frontend.Variable
	Key      frontend.Variable
	Value    frontend.Variable
	Fnc      frontend.Variable // 0: inclusion, 1: non inclusion
}

// MerkleTransition stores a pair of leaves and root hashes, and a single path common to both proofs
type MerkleTransition struct {
	// Key+Value hashed through Siblings path, should produce Root hash
	Root     frontend.Variable
	Siblings [depth]frontend.Variable
	Key      frontend.Variable
	Value    frontend.Variable

	// OldKey+OldValue hashed through same Siblings should produce OldRoot hash
	OldRoot  frontend.Variable
	OldKey   frontend.Variable
	OldValue frontend.Variable
	IsOld0   frontend.Variable
	Fnc0     frontend.Variable
	Fnc1     frontend.Variable
}

// MerkleTransitionFromProofPair generates a MerkleTransition based on the pair of proofs passed
func (o *Operator) MerkleTransitionFromProofPair(before, after ArboProof) MerkleTransition {
	//	Fnction
	//	fnc[0]  fnc[1]
	//	0       0       NOP
	//	0       1       UPDATE
	//	1       0       INSERT
	//	1       1       DELETE
	fnc0, fnc1 := 0, 0
	switch {
	case !before.Existence && !after.Existence: // exclusion, exclusion = NOOP
		fnc0, fnc1 = 0, 0
	case before.Existence && after.Existence: // inclusion, inclusion = UPDATE
		fnc0, fnc1 = 0, 1
	case !before.Existence && after.Existence: // exclusion, inclusion = INSERT
		fnc0, fnc1 = 1, 0
	case before.Existence && !after.Existence: // inclusion, exclusion = DELETE
		fnc0, fnc1 = 1, 1
	}

	isOld0 := 0
	if bytes.Equal(before.Key, []byte{}) && bytes.Equal(before.Value, []byte{}) {
		isOld0 = 1
	}

	mpBefore := MerkleProofFromArboProof(before)
	mpAfter := MerkleProofFromArboProof(after)
	return MerkleTransition{
		Root:     mpAfter.Root,
		Siblings: mpAfter.Siblings,
		Key:      mpAfter.Key,
		Value:    mpAfter.Value,
		OldRoot:  mpBefore.Root,
		OldKey:   mpBefore.Key,
		OldValue: mpBefore.Value,
		IsOld0:   isOld0,
		Fnc0:     fnc0,
		Fnc1:     fnc1,
	}
}

func (o *Operator) GenMerkleProofFromArbo(k []byte) (ArboProof, error) {
	root, err := o.ArboState.Root()
	if err != nil {
		return ArboProof{}, err
	}
	leafK, leafV, packedSiblings, existence, err := o.ArboState.GenProof(k)
	if err != nil {
		return ArboProof{}, err
	}
	unpackedSiblings, err := arbo.UnpackSiblings(arbo.HashFunctionPoseidon, packedSiblings)
	if err != nil {
		return ArboProof{}, err
	}
	fmt.Println("existence?", existence, leafK, leafV)

	return ArboProof{
		Root:      root,
		Siblings:  unpackedSiblings,
		Key:       leafK,
		Value:     leafV,
		Existence: existence,
	}, nil
}

func MerkleProofFromArboProof(p ArboProof) MerkleProof {
	fnc := 0 // inclusion
	if !p.Existence {
		fnc = 1 // non-inclusion
	}
	return MerkleProof{
		Root:     arbo.BytesLEToBigInt(p.Root),
		Siblings: padSiblings(p.Siblings),
		Key:      arbo.BytesLEToBigInt(p.Key),
		Value:    arbo.BytesLEToBigInt(p.Value),
		Fnc:      fnc,
	}
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

func (mp *MerkleTransition) VerifyProof(api frontend.API, h garbo.Hash) {
	garbo.CheckInclusionProof(api, h, mp.Key, mp.Value, mp.Root, mp.Siblings[:])
}

// VerifyProof takes a Merkle root, a proofSet, and a proofIndex and returns
// true if the first element of the proof set is a leaf of data in the Merkle
// root. False is returned if the proof set or Merkle root is nil, and if
// 'numLeaves' equals 0.
func (mp *MerkleTransition) VerifyProofPair(api frontend.API, h garbo.Hash) {
	if mp.Fnc0 == 1 && mp.Fnc1 == 0 {
		api.Println("pair of proofs is adding a leaf")
	}
	if mp.Fnc0 == 0 && mp.Fnc1 == 1 {
		api.Println("pair of proofs is updating a leaf")
	}
	if mp.Fnc0 == 1 && mp.Fnc1 == 1 {
		api.Println("pair of proofs is removing a leaf")
	}
	api.Println("key, value, root, fnc0,1", mp.Key, mp.Value, toHex(mp.Root), mp.Fnc0, mp.Fnc1)
	api.Println("oky, ovlue, orot, isold0", mp.OldKey, mp.OldValue, toHex(mp.OldRoot), mp.IsOld0)
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

	root := smt.Processor(api,
		mp.OldRoot,
		mp.Siblings[:],
		mp.OldKey,
		mp.OldValue,
		mp.IsOld0,
		mp.Key,
		mp.Value,
		mp.Fnc0,
		mp.Fnc1,
	)

	api.AssertIsEqual(root, mp.Root)

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
	api.Println("x key root", mp.Key, toHex(mp.Root), mp.Root)
	api.Println("x oky orot", mp.OldKey, toHex(mp.OldRoot), mp.OldRoot)
}

// TODO: use arbo.Hash
type arboHash *poseidon.Poseidon
