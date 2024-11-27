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
	"testing"

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

func TestOperatorVote(t *testing.T) {
	var amount uint64

	// create operator with 10 accounts
	operator := createOperator(10)

	if err := operator.initState(metadb.NewTest(t),
		[]byte{0xca, 0xfe, 0x00},
		[]byte{0xca, 0xfe, 0x01},
		[]byte{0xca, 0xfe, 0x02},
		[]byte{0xca, 0xfe, 0x03},
	); err != nil {
		t.Fatal(err)
	}

	// create the transfer and sign it
	amount = 15
	transfer := NewVote(amount)

	err := operator.updateState(transfer)
	if err != nil {
		t.Fatal(err)
	}
}

// Returns a newly created operator and the private keys of the associated accounts
func createOperator(nbVoters int) Operator {
	operator := NewOperator(nbVoters)

	return operator
}
