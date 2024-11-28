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
	"math/big"

	"go.vocdoni.io/dvote/tree/arbo"
)

// Vote describe a rollup transfer
type Vote struct {
	nullifier  []byte  // key
	ballot     big.Int // value
	address    []byte  // key
	commitment big.Int // value
}

// NewVote creates a new transfer (to be signed)
func NewVote(amount uint64) Vote {
	var v Vote

	// v.nullifier = arbo.BigIntToBytesLE(maxKeyLen, big.NewInt(int64(rand.Uint64())+16)) // mock

	v.nullifier = arbo.BigIntToBytesLE(maxKeyLen, big.NewInt(int64(1)+16)) // mock
	v.ballot.SetUint64(amount)

	v.address = arbo.BigIntToBytesLE(maxKeyLen, big.NewInt(int64(2)+16)) // mock
	v.commitment.SetUint64(amount * amount)                              // mock
	return v
}
