package rollup

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/consensys/gnark/std/hash"
)

// MerkleProof stores the leaf, the path, and the root hash.
type MerkleProof struct {
	merkle.MerkleProof
	// Leaf hashed through Path should produce RootHash
	Leaf frontend.Variable
}

// MerkleProofPair stores a pair of leaves and root hashes, and a single path common to both proofs
type MerkleProofPair struct {
	MerkleProof
	// NewLeaf hashed through the same Path should produce NewRootHash
	NewRootHash frontend.Variable
	NewLeaf     frontend.Variable
}

// VerifyProof takes a Merkle root, a proofSet, and a proofIndex and returns
// true if the first element of the proof set is a leaf of data in the Merkle
// root. False is returned if the proof set or Merkle root is nil, and if
// 'numLeaves' equals 0.
func (mp *MerkleProof) VerifyProof(api frontend.API, h hash.FieldHasher) {
	mp.MerkleProof.VerifyProof(api, h, mp.Leaf)
}

// VerifyProof takes a Merkle root, a proofSet, and a proofIndex and returns
// true if the first element of the proof set is a leaf of data in the Merkle
// root. False is returned if the proof set or Merkle root is nil, and if
// 'numLeaves' equals 0.
func (mp *MerkleProofPair) VerifyProofPair(api frontend.API, h hash.FieldHasher) {
	mp.MerkleProof.VerifyProof(api, h)
	mp.VerifyProofNew(api, h, mp.NewLeaf)
}

// VerifyProofNew is copypasta from gnark, hacked to use mp.NewRootHash
func (mp *MerkleProofPair) VerifyProofNew(api frontend.API, h hash.FieldHasher, leaf frontend.Variable) {
	depth := len(mp.Path) - 1
	sum := leafSum(api, h, mp.Path[0])

	// The binary decomposition is the bitwise negation of the order of hashes ->
	// If the path in the plain go code is 					0 1 1 0 1 0
	// The binary decomposition of the leaf index will be 	1 0 0 1 0 1 (little endian)
	binLeaf := api.ToBinary(leaf, depth)

	for i := 1; i < len(mp.Path); i++ { // the size of the loop is fixed -> one circuit per size
		d1 := api.Select(binLeaf[i-1], mp.Path[i], sum)
		d2 := api.Select(binLeaf[i-1], sum, mp.Path[i])
		sum = nodeSum(api, h, d1, d2)
	}

	// Compare our calculated Merkle root to the desired Merkle root.
	api.AssertIsEqual(sum, mp.NewRootHash)
}

// leafSum  is copypasta from gnark
func leafSum(api frontend.API, h hash.FieldHasher, data frontend.Variable) frontend.Variable {
	h.Reset()
	h.Write(data)
	res := h.Sum()

	return res
}

// nodeSum  is copypasta from gnark
func nodeSum(api frontend.API, h hash.FieldHasher, a, b frontend.Variable) frontend.Variable {
	h.Reset()
	h.Write(a, b)
	res := h.Sum()

	return res
}
