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
	"hash"
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"go.vocdoni.io/dvote/db/metadb"
)

// The tests in the package are for the rollup in plain go only, there is no snark circuits
// involved here.

type AgreggatedProofPublicInputs struct {
	ProcessId          []byte
	CensusRoot         []byte
	BallotMode         []byte
	EncryptionKey      []byte
	Nullifiers         [][]byte
	Commitments        [][]byte
	Addressess         [][]byte
	EncryptedBallots   []int
	EncryptedBallotSum int
}

func TestOutsideZKProof(t *testing.T) {
	// create operator with 10 voters
	// operator, _ := createOperator(10)

	// preimage := AgreggatedProofPublicInputs{
	// 	ProcessId:          []byte{0xca, 0xfe, 0x01},
	// 	CensusRoot:         []byte{0xca, 0xfe, 0x02},
	// 	BallotMode:         []byte{0xca, 0xfe, 0x03},
	// 	EncryptionKey:      []byte{0xca, 0xfe, 0x04},
	// 	Nullifiers:         [][]byte{},
	// 	Commitments:        [][]byte{},
	// 	Addressess:         [][]byte{},
	// 	EncryptedBallots:   []int{},
	// 	EncryptedBallotSum: 0,
	// }

	// operator.updateState()
}

func TestOperatorReadAccount(t *testing.T) {
	// create operator with 10 accounts
	operator, _ := createOperator(10)

	// check if the account read from the operator is correct
	for i := 0; i < 10; i++ {
		opAccount, err := operator.ReadAccount(uint64(i))
		if err != nil {
			t.Fatal(err)
		}
		acc, _ := createVoter(i)

		compareAccount(t, acc, opAccount)

	}
}

func TestOperatorUpdateAccount(t *testing.T) {
	var amount uint64

	// create operator with 10 accounts
	operator, _ := createOperator(10)

	if err := operator.initState(metadb.NewTest(t),
		[]byte{0xca, 0xfe, 0x00},
		[]byte{0xca, 0xfe, 0x01},
		[]byte{0xca, 0xfe, 0x02},
		[]byte{0xca, 0xfe, 0x03},
	); err != nil {
		t.Fatal(err)
	}

	// get info on the parties
	sender, err := operator.ReadAccount(0)
	if err != nil {
		t.Fatal(err)
	}

	// create the transfer and sign it
	amount = 15
	transfer := NewVote(amount, sender.pubKey)

	err = operator.updateState(transfer)
	if err != nil {
		t.Fatal(err)
	}
}

func createVoter(i int) (Voter, eddsa.PrivateKey) {
	var acc Voter
	var rnd fr.Element
	var privkey eddsa.PrivateKey

	// create account, the i-th account has a balance of 20+i
	acc.index = uint64(i)
	acc.censusRoot = uint64(i)
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

// Returns a newly created operator and the private keys of the associated accounts
func createOperator(nbVoters int) (Operator, []eddsa.PrivateKey) {
	operator := NewOperator(nbVoters)

	voterAccounts := make([]eddsa.PrivateKey, nbVoters)

	// randomly fill the accounts
	for i := 0; i < nbVoters; i++ {

		acc, privkey := createVoter(i)

		// fill the index map of the operator
		b := acc.pubKey.A.X.Bytes()
		operator.AccountMap[string(b[:])] = acc.index

		// fill user accounts list
		voterAccounts[i] = privkey
		baccount := acc.Serialize()

		copy(operator.State[SizeAccount*i:], baccount)
	}

	return operator, voterAccounts
}

func compareAccount(t *testing.T, acc1, acc2 Voter) {
	if acc1.index != acc2.index {
		t.Fatal("Incorrect index")
	}
	if acc1.censusRoot != acc2.censusRoot {
		t.Fatal("Incorrect nonce")
	}
	if !acc1.balance.Equal(&acc2.balance) {
		t.Fatal("Incorrect balance")
	}
	if !acc1.pubKey.A.X.Equal(&acc2.pubKey.A.X) {
		t.Fatal("Incorrect public key (X)")
	}
	if !acc1.pubKey.A.Y.Equal(&acc2.pubKey.A.Y) {
		t.Fatal("Incorrect public key (Y)")
	}
}

func compareHashAccount(t *testing.T, h []byte, acc Voter, hFunc hash.Hash) {
	hFunc.Reset()
	_, err := hFunc.Write(acc.Serialize())
	if err != nil {
		t.Fatal(err)
	}
	res := hFunc.Sum([]byte{})
	if len(res) != len(h) {
		t.Fatal("Error comparing hashes (different lengths)")
	}
	for i := 0; i < len(res); i++ {
		if res[i] != h[i] {
			t.Fatal("Error comparing hashes (different content)")
		}
	}
}
