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
	"fmt"
	emmy "github.com/xlab-si/emmy/crypto/common"

	"crypto/rand"
	"github.com/fentec-project/gofe/sample"
	"github.com/fentec-project/gofe/data"
)

// paillerParams represents parameters for the fully secure Paillier scheme.
type paillerParams struct {
	l int // Length of data vectors for inner product
	n *big.Int
	nSquare *big.Int
	p *big.Int
	q *big.Int
	pPrime *big.Int
	qPrime *big.Int
	g *big.Int
	boundX *big.Int
	boundY *big.Int
	sigma *big.Float
	lambda int
}

// Paillier represents a scheme based on the Paillier encryption.
type Paillier struct {
	params *paillerParams
}

// NewPaillier configures a new instance of the scheme.
// It accepts the length of input vectors l, security parameter lambda,
// the bit length of prime numbers (giving security to the scheme),
// and boundX and boundY by which coordinates of input vectors
// and inner product vectors are are bounded.
//
// It returns an error in case the scheme could not be properly
// configured, or if precondition boundX, boundY < (n / l)^(1/2)
// is not satisfied.
func NewPaillier(l, lambda int, bitLength int, boundX, boundY *big.Int) (*Paillier, error) {
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

	n := new(big.Int).Mul(p, q)
	nSquare := new(big.Int).Mul(n, n)

	xSquareL := new(big.Int).Mul(boundX, boundX)
	xSquareL.Mul(xSquareL, big.NewInt(int64(l)))
	ySquareL := new(big.Int).Mul(boundY, boundY)
	ySquareL.Mul(ySquareL, big.NewInt(int64(l)))

	if n.Cmp(xSquareL) > -1 {
		return nil, fmt.Errorf("parameters generation failed," +
			"boundX and l too big for modulusLength")
	}
	if n.Cmp(ySquareL) > -1 {
		return nil, fmt.Errorf("parameters generation failed," +
			"boundX and l too big for modulusLength")
	}

	gPrime, err := rand.Int(rand.Reader, nSquare)
	g := new(big.Int).Exp(gPrime, n, nSquare)
	g.Exp(g, big.NewInt(2), nSquare)

	// TODO check if g is appropriate, i.e. it generates the group of residues

	nTo5 := new(big.Int).Exp(n, big.NewInt(5), nil)
	sigma := new(big.Float).SetInt(nTo5)
	sigma.Mul(sigma, big.NewFloat(float64(lambda)))
	sigma.Sqrt(sigma)
	sigma.Add(sigma, big.NewFloat(2))

	return &Paillier{
		params: &paillerParams{
			l:       l,
			n:       n,
			nSquare: nSquare,
			p:       p,
			q:       q,
			pPrime:  pPrime,
			qPrime:  qPrime,
			g:       g,
			boundX:  boundX,
			boundY:  boundY,
			sigma:   sigma,
			lambda:	 lambda,
		},
	}, nil
}

// GenerateMasterKeys generates a master secret key and master
// public key for the scheme. It returns an error in case master keys
// could not be generated.
func (d *Paillier) GenerateMasterKeys() (data.Vector, data.Vector, error) {

	sampler, err := sample.NewNormalDouble(d.params.sigma, uint(d.params.lambda), big.NewFloat(1))
	secKey, err := data.NewRandomVector(d.params.l, sampler)
	if err != nil {
		return nil, nil, err
	}

	pubKey := secKey.Apply(func(x *big.Int) *big.Int {return new(big.Int).Exp(d.params.g, x, d.params.nSquare)})
	return secKey, pubKey, nil
}





