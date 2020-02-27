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

package internal

import (
	"math/big"
	"crypto/elliptic"
	"github.com/fentec-project/gofe/sample"
)

// Ec is a struct representing an element of an
// elliptic curve.
type Ec struct {
	x *big.Int
	y *big.Int
}

// P is the chosen elliptic curve.
var P = elliptic.P256()

// Set copies the value of x to e and returns e.
func (e *Ec) Set(x *Ec) *Ec {
	e.x = new(big.Int).Set(x.x)
	e.y = new(big.Int).Set(x.y)

	return e
}

// Add sets e to the sum of x and y in the
// elliptic curve. The value e is returned.
func (e *Ec) Add(x, y *Ec) *Ec {
	e.x, e.y = P.Add(x.x, x.y, y.x, y.y)

	return e
}

// Neg sets e to -x, i.e. the additive
// inverse of x in the elliptic curve.
func (e *Ec) Neg(x *Ec) *Ec {
	e.x = new(big.Int).Set(x.x)
	e.y = new(big.Int).Neg(x.y)
	e.y.Mod(e.y, P.Params().P)

	return e
}

// Gen sets e to the standard generator of the
// elliptic curve and returns the value.
func (e *Ec) Gen() *Ec {
	e.x = new(big.Int).Set(P.Params().Gx)
	e.y = new(big.Int).Set(P.Params().Gy)

	return e
}

// Unit sets e to the unit element "0" of the
// elliptic curve and returns the value.
func (e *Ec) Unit() *Ec {
	e.x = big.NewInt(0)
	e.y = big.NewInt(0)

	return e
}

// ScalarMult sets e to the value k*x (in multiplicative
// notation x^k) in the elliptic curve and returns the value.
func (e *Ec) ScalarMult(x *Ec, k *big.Int) *Ec {
	kAbs := new(big.Int).Abs(k)
	e.x, e.y = P.ScalarMult(x.x, x.y, kAbs.Bytes())
	if k.Sign() < 0 {
		e.Neg(e)
	}

	return e
}

// ScalarMult sets e to the value k*g (in multiplicative
// notation g^k) where g is the standard generator of the
// elliptic curve and returns the value.
func (e *Ec) ScalarBaseMult(k *big.Int) *Ec {
	return e.ScalarMult(new(Ec).Gen(), k)
}

// Random samples a random element of the elliptic curve.
func (e *Ec) Random() (*Ec, error) {
	sampler := sample.NewUniform(P.Params().N)
	k, err := sampler.Sample()
	if err != nil {
		return nil, err
	}

	return e.ScalarMult(new(Ec).Gen(), k), nil
}

// String returns a string representation of the
// element of the elliptic curve.
func (e *Ec) String() string {
	return e.x.String() + " " + e.y.String()
}
