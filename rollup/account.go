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
	"encoding/binary"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
)

// SizeAccount byte size of a serialized account (5*32bytes)
// index ∥ nonce ∥ balance ∥ pubkeyX ∥ pubkeyY, each chunk is 32 bytes
var SizeAccount = 160

// Voter describes a rollup account
type Voter struct {
	index   uint64 // index in the tree
	nonce   uint64 // nb transactions done so far from this account
	balance fr.Element
	pubKey  eddsa.PublicKey
}

// Reset resets an account
func (ac *Voter) Reset() {
	ac.index = 0
	ac.nonce = 0
	ac.balance.SetZero()
	ac.pubKey.A.X.SetZero()
	ac.pubKey.A.Y.SetOne()
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

// Deserialize deserializes a stream of byte in an account
func Deserialize(res *Voter, data []byte) error {
	res.Reset()

	// memory bound check
	if len(data) != SizeAccount {
		return ErrSizeByteSlice
	}

	res.index = binary.BigEndian.Uint64(data[24:32])
	res.nonce = binary.BigEndian.Uint64(data[56:64])
	res.balance.SetBytes(data[64:96])
	res.pubKey.A.X.SetBytes(data[96:128])
	res.pubKey.A.Y.SetBytes(data[128:])

	return nil
}
