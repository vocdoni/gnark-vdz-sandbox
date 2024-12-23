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
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/test"
	"github.com/rs/zerolog"
)

type circuitVerifyResults Circuit

// Circuit implements part of the rollup circuit only by declaring a subset of the constraints
func (t *circuitVerifyResults) Define(api frontend.API) error {
	// TODO: refactor Circuit methods to be able to Define subsets of constraints
	// verifyResults(api, t.BallotSum,
	// 	t.ResultsAdd.OldValue, t.ResultsAdd.NewValue,
	// )
	return nil
}

func TestCircuitFull(t *testing.T) {
	operator := newTestOperator(t)

	// first batch
	if err := operator.StartBatch(); err != nil {
		t.Fatal(err)
	}
	if err := operator.AddVote(NewVote(1, 10)); err != nil { // new vote 1
		t.Fatal(err)
	}
	if err := operator.AddVote(NewVote(2, 20)); err != nil { // new vote 2
		t.Fatal(err)
	}
	if err := operator.EndBatch(); err != nil { // expected result: 16+17=33
		t.Fatal(err)
	}
	assert := test.NewAssert(t)

	var fullCircuit Circuit

	assert.ProverSucceeded(
		&fullCircuit,
		&operator.Witnesses,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16))

	debugLog(t, operator)

	// second batch
	if err := operator.StartBatch(); err != nil {
		t.Fatal(err)
	}
	if err := operator.AddVote(NewVote(1, 100)); err != nil { // overwrite vote 1
		t.Fatal(err)
	}
	if err := operator.AddVote(NewVote(3, 30)); err != nil { // add vote 3
		t.Fatal(err)
	}
	if err := operator.EndBatch(); err != nil {
		t.Fatal(err)
	}
	// expected results:
	// ResultsAdd: 16+17+10+100 = 143
	// ResultsSub: 16 = 16
	// Final: 16+17-16+10+100 = 127
	assert.ProverSucceeded(
		&fullCircuit,
		&operator.Witnesses,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16))

	debugLog(t, operator)
}

func TestCircuitCompile(t *testing.T) {
	// enable log to see nbConstraints
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())

	var fullCircuit Circuit

	_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &fullCircuit)
	if err != nil {
		panic(err)
	}
}

func debugLog(t *testing.T, operator Operator) {
	t.Log("public: RootHashBefore", prettyHex(operator.Witnesses.RootHashBefore))
	t.Log("public: RootHashAfter", prettyHex(operator.Witnesses.RootHashAfter))
	t.Log("public: NumVotes", prettyHex(operator.Witnesses.NumNewVotes))
	t.Log("public: NumOverwrites", prettyHex(operator.Witnesses.NumOverwrites))
	for name, mt := range map[string]MerkleTransition{
		"ResultsAdd": operator.Witnesses.ResultsAdd,
		"ResultsSub": operator.Witnesses.ResultsSub,
	} {
		t.Log(name, "transitioned", "(root", prettyHex(mt.OldRoot), "->", prettyHex(mt.NewRoot), ")",
			"value", mt.OldValue, "->", mt.NewValue,
		)
	}
}

func debugWitness(wit Circuit) {
	js, _ := json.MarshalIndent(wit, "", "  ")
	fmt.Printf("\n\n%s\n\n", js)
}
