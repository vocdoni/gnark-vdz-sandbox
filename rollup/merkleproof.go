package rollup

import (
	"bytes"
	"math/big"

	"github.com/consensys/gnark/frontend"
	garbo "github.com/vocdoni/gnark-crypto-primitives/arbo"
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

func (o *Operator) GenArboProof(k []byte) (ArboProof, error) {
	root, err := o.state.Root()
	if err != nil {
		return ArboProof{}, err
	}
	leafK, leafV, packedSiblings, existence, err := o.state.GenProof(k)
	if err != nil {
		return ArboProof{}, err
	}
	unpackedSiblings, err := arbo.UnpackSiblings(arbo.HashFunctionPoseidon, packedSiblings)
	if err != nil {
		return ArboProof{}, err
	}
	return ArboProof{
		Root:      root,
		Siblings:  unpackedSiblings,
		Key:       leafK,
		Value:     leafV,
		Existence: existence,
	}, nil
}

// MerkleProof stores the leaf, the path, and the root hash.
type MerkleProof struct {
	// Key + Value hashed through Siblings path, should produce Root hash
	Root     frontend.Variable
	Siblings [maxLevels]frontend.Variable
	Key      frontend.Variable
	Value    frontend.Variable
	Fnc      frontend.Variable // 0: inclusion, 1: non inclusion
}

func (o *Operator) GenMerkleProofFromArbo(k []byte) (MerkleProof, error) {
	p, err := o.GenArboProof(k)
	if err != nil {
		return MerkleProof{}, err
	}
	return MerkleProofFromArboProof(p), nil
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

func padSiblings(unpackedSiblings [][]byte) [maxLevels]frontend.Variable {
	paddedSiblings := [maxLevels]frontend.Variable{}
	for i := range maxLevels {
		if i < len(unpackedSiblings) {
			paddedSiblings[i] = arbo.BytesLEToBigInt(unpackedSiblings[i])
		} else {
			paddedSiblings[i] = big.NewInt(0)
		}
	}
	return paddedSiblings
}

// Verify uses garbo.CheckInclusionProof to verify that:
//   - mp.Root matches passed root
//   - Key + Value belong to Root
func (mp *MerkleProof) VerifyProof(api frontend.API, hFn garbo.Hash, root frontend.Variable) {
	api.AssertIsEqual(root, mp.Root)

	if err := garbo.CheckInclusionProof(api, hFn, mp.Key, mp.Value, mp.Root, mp.Siblings[:]); err != nil {
		panic(err)
	}
}

// MerkleTransition stores a pair of leaves and root hashes, and a single path common to both proofs
type MerkleTransition struct {
	// NewKey + NewValue hashed through Siblings path, should produce NewRoot hash
	NewRoot  frontend.Variable
	Siblings [maxLevels]frontend.Variable
	NewKey   frontend.Variable
	NewValue frontend.Variable

	// OldKey + OldValue hashed through same Siblings should produce OldRoot hash
	OldRoot  frontend.Variable
	OldKey   frontend.Variable
	OldValue frontend.Variable
	IsOld0   frontend.Variable
	Fnc0     frontend.Variable
	Fnc1     frontend.Variable
}

// MerkleTransitionFromArboProofPair generates a MerkleTransition based on the pair of proofs passed
func MerkleTransitionFromArboProofPair(before, after ArboProof) MerkleTransition {
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
		Siblings: mpBefore.Siblings,
		OldRoot:  mpBefore.Root,
		OldKey:   mpBefore.Key,
		OldValue: mpBefore.Value,
		NewRoot:  mpAfter.Root,
		NewKey:   mpAfter.Key,
		NewValue: mpAfter.Value,
		IsOld0:   isOld0,
		Fnc0:     fnc0,
		Fnc1:     fnc1,
	}
}

// Verify uses smt.Processor to verify that:
//   - mp.OldRoot matches passed oldRoot
//   - OldKey + OldValue belong to OldRoot
//   - NewKey + NewValue belong to NewRoot
//   - no other changes were introduced between OldRoot -> NewRoot
//
// and returns mp.NewRoot
func (mp *MerkleTransition) Verify(api frontend.API, oldRoot frontend.Variable) frontend.Variable {
	mp.printDebugLog(api)

	api.AssertIsEqual(oldRoot, mp.OldRoot)

	root := smt.Processor(api,
		mp.OldRoot,
		mp.Siblings[:],
		mp.OldKey,
		mp.OldValue,
		mp.IsOld0,
		mp.NewKey,
		mp.NewValue,
		mp.Fnc0,
		mp.Fnc1,
	)

	api.AssertIsEqual(root, mp.NewRoot)
	return mp.NewRoot
}

func (mp *MerkleTransition) printDebugLog(api frontend.API) {
	api.Println("proving transition", prettyHex(mp.OldRoot), "->", prettyHex(mp.NewRoot))
	api.Println("old key, value, root, isold0 = ", mp.OldKey, mp.OldValue, prettyHex(mp.OldRoot), mp.IsOld0)
	api.Println("new key, value, root, fnc0,1 = ", mp.NewKey, mp.NewValue, prettyHex(mp.NewRoot), mp.Fnc0, mp.Fnc1)
	for i := range mp.Siblings {
		api.Println("siblings", prettyHex(mp.Siblings[i]))
	}
}
