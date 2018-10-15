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
	"fmt"
	"math/big"

	emmy "github.com/xlab-si/emmy/crypto/common"

	"crypto/rand"

	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/sample"
)

// paillerParams represents parameters for the fully secure Paillier scheme.
type paillerParams struct {
	l       int        // Length of data vectors for inner product
	n       *big.Int   // a big integer, a product of two safe primes
	nSquare *big.Int   // n^2 a modulus for computations
	boundX  *big.Int   // a bound on the entries of the input vector
	boundY  *big.Int   // a bound on the entries of the inner product vector
	sigma   *big.Float // the standard deviation for the sampling a secret key
	lambda  int        // safety parameter
	g       *big.Int   // generator of the 2n-th residues subgroup of Z_n^2*
}

// Paillier represents a scheme based on the Paillier encryption.
type Paillier struct {
	Params *paillerParams
}

// NewPaillier configures a new instance of the scheme.
// It accepts the length of input vectors l, security parameter lambda,
// the bit length of prime numbers (giving security to the scheme, it
// should be such that factoring two primes with such a bit length takes
// at least 2^lambda operations), and boundX and boundY by which
// coordinates of input vectors and inner product vectors are are bounded.
//
// It returns an error in case the scheme could not be properly
// configured, or if precondition boundX, boundY < (n / l)^(1/2)
// is not satisfied.
func NewPaillier(l, lambda int, bitLength int, boundX, boundY *big.Int) (*Paillier, error) {
	// generate two safe primes
	p, err := emmy.GetSafePrime(bitLength)
	if err != nil {
		return nil, err
	}
	pPrime := new(big.Int).Sub(p, big.NewInt(1))
	pPrime.Quo(pPrime, big.NewInt(2))

	q, err := emmy.GetSafePrime(bitLength)
	if err != nil {
		return nil, err
	}

	qPrime := new(big.Int).Sub(q, big.NewInt(1))
	pPrime.Quo(qPrime, big.NewInt(2))

	// calculate n = p * q
	n := new(big.Int).Mul(p, q)

	// calculate n^2
	nSquare := new(big.Int).Mul(n, n)

	// check if the parameters of the scheme are compatible,
	// i.e. security parameter should be big enough that
	// the generated n is much greater than l and the bounds
	xSquareL := new(big.Int).Mul(boundX, boundX)
	xSquareL.Mul(xSquareL, big.NewInt(int64(l)))
	ySquareL := new(big.Int).Mul(boundY, boundY)
	ySquareL.Mul(ySquareL, big.NewInt(int64(l)))
	if n.Cmp(xSquareL) < 1 {
		return nil, fmt.Errorf("parameters generation failed," +
			"boundX and l too big for bitLength")
	}
	if n.Cmp(ySquareL) < 1 {
		return nil, fmt.Errorf("parameters generation failed," +
			"boundX and l too big for bitLength")
	}

	// generate a generator for the 2n-th residues subgroup of Z_n^2*
	gPrime, err := rand.Int(rand.Reader, nSquare)
	g := new(big.Int).Exp(gPrime, n, nSquare)
	g.Exp(g, big.NewInt(2), nSquare)

	// check if generated g is invertible, which should be the case except with
	// negligible probability
	check := g.ModInverse(g, nSquare)
	if check == nil {
		return nil, fmt.Errorf("parameters generation failed," +
			"unexpected event of generator g is not invertible")
	}

	// calculate sigma
	nTo5 := new(big.Int).Exp(n, big.NewInt(5), nil)
	sigma := new(big.Float).SetInt(nTo5)
	sigma.Mul(sigma, big.NewFloat(float64(lambda)))
	sigma.Sqrt(sigma)
	sigma.Add(sigma, big.NewFloat(2))
	sigmaI, _ := sigma.Int(nil)
	sigma.SetInt(sigmaI)

	return &Paillier{
		Params: &paillerParams{
			l:       l,
			n:       n,
			nSquare: nSquare,
			boundX:  boundX,
			boundY:  boundY,
			sigma:   sigma,
			lambda:  lambda,
			g:       g,
		},
	}, nil
}

// NewPaillierFromParams takes configuration parameters of an existing
// Paillier scheme instance, and reconstructs the scheme with same configuration
// parameters. It returns a new Paillier instance.
func NewPaillierFromParams(params *paillerParams) *Paillier {
	return &Paillier{
		Params: params,
	}
}

// GenerateMasterKeys generates a master secret key and a master
// public key for the scheme. It returns an error in case master keys
// could not be generated.
func (d *Paillier) GenerateMasterKeys() (data.Vector, data.Vector, error) {
	// sampler for sampling a secret key
	sampler, err := sample.NewNormalDouble(d.Params.sigma, uint(d.Params.lambda),
		big.NewFloat(1), false)
	if err != nil {
		return nil, nil, err
	}
	// generate a secret key
	secKey, err := data.NewRandomVector(d.Params.l, sampler)
	if err != nil {
		return nil, nil, err
	}

	// derive the public key from the generated secret key
	pubKey := secKey.Apply(func(x *big.Int) *big.Int {
		return ModExp(d.Params.g,
			x, d.Params.nSquare)
	})
	return secKey, pubKey, nil
}

// DeriveKey accepts input master secret key SK and vector y, and derives a
// functional encryption key for the inner product with y.
// In case of malformed secret key or input vector that violates the configured
// bound, it returns an error.
func (d *Paillier) DeriveKey(masterSecKey data.Vector, y data.Vector) (*big.Int, error) {
	if err := y.CheckBound(d.Params.boundY); err != nil {
		return nil, err
	}

	key, err := masterSecKey.Dot(y)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// Encrypt encrypts input vector x with the provided master public key.
// It returns a ciphertext vector. If encryption failed, error is returned.
func (d *Paillier) Encrypt(x, masterPubKey data.Vector) (data.Vector, error) {
	if err := x.CheckBound(d.Params.boundX); err != nil {
		return nil, err
	}

	// generate a randomness for the encryption
	nOver4 := new(big.Int).Quo(d.Params.n, big.NewInt(4))
	r, err := rand.Int(rand.Reader, nOver4)
	if err != nil {
		return nil, err
	}

	// encrypt x under randomness r
	ciphertext := make([]*big.Int, d.Params.l+1)
	// c_0 = g^r in Z_n^2
	c0 := new(big.Int).Exp(d.Params.g, r, d.Params.nSquare)
	ciphertext[0] = c0
	for i := 0; i < d.Params.l; i++ {
		// c_i = (1 + x_i * n) * pubKey_i^r in Z_n^2
		t1 := new(big.Int).Mul(x[i], d.Params.n)
		t1.Add(t1, big.NewInt(1))
		t1.Mod(t1, d.Params.nSquare)
		t2 := new(big.Int).Exp(masterPubKey[i], r, d.Params.nSquare)
		ct := new(big.Int).Mul(t1, t2)
		ct.Mod(ct, d.Params.nSquare)
		ciphertext[i+1] = ct
	}

	return data.NewVector(ciphertext), nil
}

// Decrypt accepts the encrypted vector, functional encryption key, and
// a vector y. It returns the inner product of x and y.
func (d *Paillier) Decrypt(cipher data.Vector, key *big.Int, y data.Vector) *big.Int {
	// tmp value cX is calculated as (prod_{i=1 to l) c_i^y_i) * c_0^(-key) in Z_n^2
	keyNeg := new(big.Int).Neg(key)
	cX := ModExp(cipher[0], keyNeg, d.Params.nSquare)

	for i, ct := range cipher[1:] {
		t1 := ModExp(ct, y[i], d.Params.nSquare)
		cX.Mul(cX, t1)
		cX.Mod(cX, d.Params.nSquare)
	}

	// decryption is calculated as (cX-1 mod n^2)/n
	cX.Sub(cX, big.NewInt(1))
	cX.Mod(cX, d.Params.nSquare)
	ret := new(big.Int).Quo(cX, d.Params.n)
	// if the return value is negative this is seen as the above ret beaing
	// greater than n/2; in this case ret = ret - n
	nHalf := new(big.Int).Quo(d.Params.n, big.NewInt(2))
	if ret.Cmp(nHalf) == 1 {
		ret.Sub(ret, d.Params.n)
	}

	return ret
}

// TODO: where should this function be: maybe even in emmy?
// modExp calculates g^x in Z_m*, even if x < 0
func ModExp(g, x, m *big.Int) *big.Int {
	ret := new(big.Int)
	if x.Cmp(big.NewInt(0)) == -1 {
		xNeg := new(big.Int).Neg(x)
		ret.Exp(g, xNeg, m)
		ret.ModInverse(ret, m)
	} else {
		ret.Exp(g, x, m)
	}
	return ret
}
