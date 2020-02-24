/*
 * Copyright (c) 2018 XLAB d.o.o
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fullysec

import (
	"math/big"

	"github.com/fentec-project/gofe/internal"
	"github.com/fentec-project/gofe/internal/dlog"
	"fmt"
	"github.com/fentec-project/gofe/sample"
	"github.com/fentec-project/gofe/data"
)

// ECIPEParams includes public parameters for the ECIPE scheme.
// L (int): The length of vectors to be encrypted.
// Bound (int): The value by which coordinates of vectors x and y are bounded.
// Order (int): Order of the elliptic curve group.
// G (int): A generator of the elliptic group.
// H (int): Another generator of the elliptic group.

type ECIPEParams struct {
	L     int
	Bound *big.Int
	Order *big.Int
	G 	  *internal.Ec
	H 	  *internal.Ec
}

// ECIPE (elliptic curve inner product encryption) represents a
// scheme instantiated from the DDH assumption in an elliptic
// curve group P256, based on the DDH variant of Agrawal, Shweta,
// Libert, and Stehle:
// "Fully secure functional encryption for inner products,
// from standard assumptions".
type ECIPE struct {
	Params *ECIPEParams
}

// NewECIPE configures a new instance of the scheme.
// It accepts the length of input vectors l and a bound by which
// coordinates of input vectors are bounded.
//
// It returns an error in case the scheme could not be properly
// configured, or if precondition 2 * l * bound² is >= order of the cyclic
// group.
func NewECIPE(l int, bound *big.Int) (*ECIPE, error) {
	order := internal.P.Params().N

	bSquared := new(big.Int).Exp(bound, big.NewInt(2), nil)
	prod := new(big.Int).Mul(big.NewInt(int64(2*l)), bSquared)
	if prod.Cmp(order) > 0 {
		return nil, fmt.Errorf("2 * l * bound^2 should be smaller than group order")
	}

	h, err := new(internal.Ec).Random()
	if err != nil {
		return nil, err
	}

	return &ECIPE{
		Params: &ECIPEParams{
			L:     l,
			Bound: bound,
			Order: order,
			G:     new(internal.Ec).Gen(),
			H:     h,
		},
	}, nil
}


// NewECIPEFromParams takes configuration parameters of an existing
// ECIPE scheme instance, and reconstructs the scheme with same configuration
// parameters. It returns a new ECIPE instance.
func NewECIPEFromParams(params *ECIPEParams) *ECIPE {
	return &ECIPE{
		Params: params,
	}
}

// ECIPESecKey is a secret key for ECIPE scheme.
type ECIPESecKey struct {
	S data.Vector
	T data.Vector
}

// GenerateKeys generates a master secret key and a public
// key for the scheme. It returns an error in case master keys
// could not be generated.
func (e *ECIPE) GenerateKeys() (*ECIPESecKey, data.VectorEC, error) {
	mskS := make(data.Vector, e.Params.L)
	mskT := make(data.Vector, e.Params.L)

	masterPubKey := make(data.VectorEC, e.Params.L)
	sampler := sample.NewUniformRange(big.NewInt(2), e.Params.Order)

	for i := 0; i < e.Params.L; i++ {
		s, err := sampler.Sample()
		if err != nil {
			return nil, nil, err
		}
		mskS[i] = s

		t, err := sampler.Sample()
		if err != nil {
			return nil, nil, err
		}
		mskT[i] = t

		y1 := new(internal.Ec).ScalarMult(e.Params.G, s)
		y2 := new(internal.Ec).ScalarMult(e.Params.H, t)

		masterPubKey[i] = new(internal.Ec).Add(y1, y2)
	}

	return &ECIPESecKey{S: mskS, T: mskT}, masterPubKey, nil
}

// ECIPEDerivedKey is a functional encryption key for ECIPE scheme.
type ECIPEDerivedKey struct {
	Key1 *big.Int
	Key2 *big.Int
}

// DeriveKey takes master secret key and input vector y, and returns the
// functional encryption key. In case the key could not be derived, it
// returns an error.
func (e *ECIPE) DeriveKey(masterSecKey *ECIPESecKey, y data.Vector) (*ECIPEDerivedKey, error) {
	if err := y.CheckBound(e.Params.Bound); err != nil {
		return nil, err
	}

	key1, err := masterSecKey.S.Dot(y)
	if err != nil {
		return nil, err
	}

	key2, err := masterSecKey.T.Dot(y)
	if err != nil {
		return nil, err
	}

	k1 := new(big.Int).Mod(key1, e.Params.Order)
	k2 := new(big.Int).Mod(key2, e.Params.Order)

	return &ECIPEDerivedKey{Key1: k1, Key2: k2}, nil
}

// Encrypt encrypts input vector x with the provided public key.
// It returns a ciphertext vector. If encryption failed, an error is returned.
func (e *ECIPE) Encrypt(x data.Vector, masterPubKey data.VectorEC) (data.VectorEC, error) {
	if err := x.CheckBound(e.Params.Bound); err != nil {
		return nil, err
	}

	sampler := sample.NewUniformRange(big.NewInt(2), e.Params.Order)
	r, err := sampler.Sample()
	if err != nil {
		return nil, err
	}

	ciphertext := make(data.VectorEC, len(x)+2)
	c := new(internal.Ec).ScalarMult(e.Params.G, r)
	ciphertext[0] = c
	dd := new(internal.Ec).ScalarMult(e.Params.H, r)
	ciphertext[1] = dd

	for i := 0; i < len(x); i++ {
		t1 := new(internal.Ec).ScalarMult(masterPubKey[i], r)
		t2 := new(internal.Ec).ScalarMult(e.Params.G, x[i])
		ct := new(internal.Ec).Add(t1, t2)
		ciphertext[i+2] = ct
	}

	return ciphertext, nil
}

// Decrypt accepts the encrypted vector, functional encryption key, and
// a plaintext vector y. It returns the inner product of x and y.
// If decryption failed, an error is returned.
func (e *ECIPE) Decrypt(cipher data.VectorEC, key *ECIPEDerivedKey, y data.Vector) (*big.Int, error) {
	if err := y.CheckBound(e.Params.Bound); err != nil {
		return nil, err
	}

	num := new(internal.Ec).Unit()
	for i, ct := range cipher[2:] {
		t1 := new(internal.Ec).ScalarMult(ct, y[i])
		num.Add(num, t1)
	}

	t1 := new(internal.Ec).ScalarMult(cipher[0], key.Key1)
	t2 := new(internal.Ec).ScalarMult(cipher[1], key.Key2)

	denom := new(internal.Ec).Add(t1, t2)
	denomInv := new(internal.Ec).Neg(denom)
	r := new(internal.Ec).Add(num, denomInv)

	bSquared := new(big.Int).Exp(e.Params.Bound, big.NewInt(2), big.NewInt(0))
	bound := new(big.Int).Mul(big.NewInt(int64(e.Params.L)), bSquared)

	calc := dlog.NewCalc().InEC()
	calc = calc.WithNeg()
	res, err := calc.WithBound(bound).BabyStepGiantStep(r, e.Params.G)

	return res, err
}
