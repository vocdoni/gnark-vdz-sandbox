package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand"

	"gnark-vdz/rollup"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/test"
)

type simplerCircuit rollup.Circuit

const (
	BatchSizeCircuit = 1 // nbTranfers to batch in a proof
	depth            = 5 // size fo the inclusion proofs
)

func (circuit *simplerCircuit) postInit(api frontend.API) error {
	for i := 0; i < BatchSizeCircuit; i++ {

		// setting the sender accounts before update
		circuit.ProcessBefore[i].EncryptionKey = circuit.PublicKeysSender[i]

		// setting the sender accounts after update
		circuit.ProcessAfter[i].EncryptionKey = circuit.PublicKeysSender[i]

		// setting the transfers
		circuit.Votes[i].Nonce = circuit.ProcessBefore[i].CensusRoot
		api.Println("XXXXXXXXXXXXXXXXXXXXXX setting SenderPubKey")
		circuit.Votes[i].SenderPubKey = circuit.PublicKeysSender[i]

		// allocate the slices for the Merkle proofs
		// circuit.allocateSlicesMerkleProofs()

	}
	return nil
}

// Circuit implements part of the rollup circuit only by declaring a subset of the constraints
func (circuit simplerCircuit) Define(api frontend.API) error {
	if err := circuit.postInit(api); err != nil {
		return err
	}

	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	for i := 0; i < BatchSizeCircuit; i++ {
		api.AssertIsEqual(circuit.RootHashesBefore[i], circuit.MerkleProofSenderBefore[i].RootHash)
		api.AssertIsEqual(circuit.RootHashesAfter[i], circuit.MerkleProofSenderAfter[i].RootHash)
		api.Println(fmt.Printf("MerkleProofSenderBefore: %+v", circuit.MerkleProofSenderBefore[i]))
		api.Println("OK")

		circuit.MerkleProofSenderBefore[i].VerifyProof(api, &hFunc, circuit.LeafSender[i])
		circuit.MerkleProofSenderAfter[i].VerifyProof(api, &hFunc, circuit.LeafSender[i])
		hFunc.Write(big.NewInt(int64(1)))
		api.Println(hFunc.Sum())
	}
	return nil
}

// Voter describes a rollup account
type Voter struct {
	index   uint64 // index in the tree
	nonce   uint64 // nb transactions done so far from this account
	balance fr.Element
	pubKey  eddsa.PublicKey
}

func createVoter(i int) (Voter, eddsa.PrivateKey) {
	var acc Voter
	var rnd fr.Element
	var privkey eddsa.PrivateKey

	// create account, the i-th account has a balance of 20+i
	acc.index = uint64(i)
	acc.nonce = uint64(i)
	acc.balance.SetUint64(uint64(i) + 20)
	rnd.SetUint64(uint64(i))
	src := rand.NewSource(int64(i))
	r := rand.New(src)

	pkey, err := eddsa.GenerateKey(r)
	if err != nil {
		panic(err)
	}
	privkey = *pkey

	acc.pubKey = privkey.PublicKey

	return acc, privkey
}

// Serialize serializes the account as a concatenation of 5 chunks of 256 bits
// one chunk per field (pubKey has 2 chunks), except index and nonce that are concatenated in a single 256 bits chunk
// index ∥ nonce ∥ balance ∥ pubkeyX ∥ pubkeyY, each chunk is 256 bits
func (ac *Voter) Serialize() []byte {
	// var buffer bytes.Buffer
	var res [160]byte

	// first chunk of 256 bits
	binary.BigEndian.PutUint64(res[24:], ac.index) // index is on 64 bits, so fill the last chunk of 64bits in the first 256 bits slot
	binary.BigEndian.PutUint64(res[56:], ac.nonce) // same for nonce

	// balance
	buf := ac.balance.Bytes()
	copy(res[64:], buf[:])

	// public key
	buf = ac.pubKey.A.X.Bytes()
	copy(res[96:], buf[:])
	buf = ac.pubKey.A.Y.Bytes()
	copy(res[128:], buf[:])

	return res[:]
}

var SizeAccount = 160

// Returns a newly created operator and the private keys of the associated accounts
func createOperator(nbVoters int) (rollup.Operator, []eddsa.PrivateKey) {
	operator := rollup.NewOperator(nbVoters)

	userAccounts := make([]eddsa.PrivateKey, nbVoters)

	for i := 0; i < BatchSizeCircuit; i++ {
		// allocating slice for the Merkle paths
		operator.Witnesses.MerkleProofSenderBefore[i].Path = make([]frontend.Variable, depth)
		operator.Witnesses.MerkleProofSenderAfter[i].Path = make([]frontend.Variable, depth)
	}

	// randomly fill the accounts
	for i := 0; i < nbVoters; i++ {

		acc, privkey := createVoter(i)

		// fill the index map of the operator
		b := acc.pubKey.A.X.Bytes()
		operator.AccountMap[string(b[:])] = acc.index

		// fill user accounts list
		userAccounts[i] = privkey
		baccount := acc.Serialize()

		copy(operator.State[SizeAccount*i:], baccount)

		// create the list of hashes of account
		operator.H().Reset()
		operator.H().Write(acc.Serialize())
		buf := operator.H().Sum([]byte{})
		copy(operator.HashState[operator.H().Size()*i:], buf)
	}

	return operator, userAccounts
}

func main() {
	// compiles our circuit into a R1CS
	var circuit simplerCircuit
	for i := 0; i < BatchSizeCircuit; i++ {
		// allocating slice for the Merkle paths
		circuit.MerkleProofSenderBefore[i].Path = make([]frontend.Variable, depth)
		circuit.MerkleProofSenderAfter[i].Path = make([]frontend.Variable, depth)
	}
	p := profile.Start()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}
	p.Stop()
	fmt.Println("constraints", p.NbConstraints())
	// groth16 zkSNARK: Setup
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}
	op, userKeys := createOperator(10)

	// get info on the parties
	sender, err := op.ReadAccount(0)
	if err != nil {
		panic(err)
	}

	receiver, err := op.ReadAccount(1)
	if err != nil {
		panic(err)
	}

	// create the transfer and sign it
	{
		amount := uint64(10)
		transfer := rollup.NewVote(amount, sender.PubKey(), receiver.PubKey(), 0)
		transfer.Sign(userKeys[0], op.H())

		err = op.UpdateState(transfer, 0)
		if err != nil {
			panic(err)
		}
	}

	fmt.Printf("%+v", op.Witnesses)
	debugCircuit := rollup.DebugCircuit{}
	debugCircuit.RootHashesBefore[0] = []byte{0x00}
	debugCircuit.RootHashesAfter[0] = []byte{0x00}
	debugCircuit.LeafSender[0] = []byte{0x00}

	for i := 0; i < BatchSizeCircuit; i++ {
		// allocating slice for the Merkle paths
		debugCircuit.MerkleProofSenderBefore[i].RootHash = []byte{0x00}
		debugCircuit.MerkleProofSenderBefore[i].Path = make([]frontend.Variable, depth)
		debugCircuit.MerkleProofSenderAfter[i].RootHash = []byte{0x00}
		debugCircuit.MerkleProofSenderAfter[i].Path = make([]frontend.Variable, depth)

		for j := 0; j < depth; j++ {
			debugCircuit.MerkleProofSenderBefore[i].Path[j] = []byte{0x01}
			debugCircuit.MerkleProofSenderAfter[i].Path[j] = []byte{0x00}
		}
	}

	wit := op.Witnesses
	js, _ := json.MarshalIndent(wit, "", "  ")
	fmt.Printf("\n\n%s\n\n", js)

	witness, err := frontend.NewWitness(wit, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}

	if err := test.IsSolved(&circuit, debugCircuit, ecc.BN254.ScalarField()); err != nil {
		panic(err)
	}

	// groth16: Prove & Verify
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		panic(err)
	}

	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		panic(err)
	}
}
