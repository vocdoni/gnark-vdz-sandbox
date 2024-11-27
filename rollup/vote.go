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
)

// Vote describe a rollup transfer
type Vote struct {
	ballot     big.Int
	nullifier  []byte
	commitment []byte
	address    []byte
}

// NewVote creates a new transfer (to be signed)
func NewVote(amount uint64) Vote {
	var res Vote

	res.ballot.SetUint64(amount)

	return res
}
