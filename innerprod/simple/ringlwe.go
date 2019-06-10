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

package simple

import (
	"math/big"

	"fmt"

	"github.com/fentec-project/gofe/data"
	gofe "github.com/fentec-project/gofe/internal"
	"github.com/fentec-project/gofe/sample"
	"github.com/pkg/errors"
	"math"
	"crypto/rand"
)

// RingLWEParams represents parameters for the ring LWE scheme.
type RingLWEParams struct {
	L     int        // Length of data vectors for inner product

			 // Main security parameters of the scheme
	N     int

			 // Settings for discrete gaussian sampler
	Sigma *big.Float // standard deviation for the security
	Sigma1 *big.Float // standard deviation for the secret
	Sigma2 *big.Float // standard deviation	for the first part of ciphertext
	Sigma3 *big.Float // standard deviation for the second part of ciphertext

	Bound *big.Int   // upper bound for coordinates of input vectors

	P     *big.Int   // modulus for the resulting inner product
	Q     *big.Int   // modulus for ciphertext and keys

			 // A is a vector with N coordinates.
			 // It represents a random polynomial for the scheme.
	A     data.Vector
}

// RingLWE represents a scheme instantiated from the LWE problem,
// that is much more efficient than the LWE scheme. It operates in the
// ring of polynomials R = Z[x]/((x^n)+1).
type RingLWE struct {
	Params  *RingLWEParams
	Sampler1 *sample.NormalDouble
	Sampler2 *sample.NormalCumulative
	Sampler3 *sample.NormalDouble
}

// NewRingLWE configures a new instance of the scheme.
// It accepts the length of input vectors l, the main security parameter
// n, upper bound for coordinates of input vectors x and y, modulus for the
// inner product p, modulus for ciphertext and keys q, and parameters
// for the sampler: standard deviation sigma, precision eps and a limit
// k for the sampling interval.
//
// Note that the security parameter n must be a power of 2.
// In addition, modulus p must be strictly smaller than l*bound². If
// any of these conditions is violated, or if public parameters
// for the scheme cannot be generated for some other reason,
// an error is returned.
func NewRingLWE(l, sec int, bound *big.Int) (*RingLWE, error) {
	p := new(big.Int).Mul(bound, big.NewInt(int64(l * 2)))
	p.Mul(p, bound)
	p.Add(p, big.NewInt(1))
	pF := new(big.Float).SetInt(p)
	boundF := new(big.Float).SetInt(bound)

	b := float64(sec) / 0.265
	//b := float64(sec) / 0.2075
	fmt.Println("b", b)
	delta := math.Pow(math.Pow(math.Pi * b, 1 / b) * b / (2 * math.Pi * math.E), 1. / (2. * b - 2.))
	fmt.Println("delta", delta)
	fmt.Println("p", p, p.BitLen())
	var q *big.Int
	var qF, sigma *big.Float
	var sigmaF float64
	var safe bool
	var tmp float64;
	var n int;
	for pow := 6; pow < 20; pow++ {
		n = 1<<uint(pow)
		for i := 2 * p.BitLen(); i < 1024; i++ {
			for {
				//q, _ = rand.Prime(rand.Reader, i)
				q, _ = rand.Int(rand.Reader, new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(i - pow)), nil))
				q.Mul(q, big.NewInt(int64(2 * n)))
				q.Add(q, big.NewInt(1))
				if q.ProbablyPrime(20) == true {
					break
				}
			}

			qF = new(big.Float).SetInt(q)

			tmp = math.Sqrt(float64(4*sec*l+1)) + 2*math.Sqrt(float64(2*sec))
			tmp = tmp * 2 * float64(l) * math.Sqrt(float64(n*sec*2*l))
			tmp = math.Sqrt(tmp)

			sigma = new(big.Float).Quo(qF, pF)
			sigma = sigma.Sqrt(sigma)
			sigma.Quo(sigma, boundF)
			sigma.Quo(sigma, big.NewFloat(tmp))

			sigmaF, _ = sigma.Float64()
			if sigmaF >= 1 {
				break
			}
		}

		//fmt.Println(sigmaF)

		qFF, _ := qF.Float64()
		//fmt.Println("kvocient", qFF/sigmaF)
		safe = true

		for mForTest := n; mForTest <= 2*n; mForTest++ {
			d := n + mForTest
			left := sigmaF * math.Sqrt(b)
			right := math.Pow(delta, (2*b)-float64(d)-1) * math.Pow(qFF, float64(mForTest)/float64(d))
			//fmt.Println(left, right)
			//fmt.Println(right / left)
			if left < right {
				safe = false
				break
			}
		}
		if safe {
			//fmt.Println(math.Log2(sigmaF))
			break
		}
	}
	if safe == false {
		return nil, fmt.Errorf("cannot generate public parameters")
	}

	fmt.Println("n", n)

	//// make sigmaQ an integer for faster sampling using NormalDouble
	sigmaI, _ := sigma.Int(nil)
	//sigma.SetInt(sigmaI)
	//sigma.Add(sigma, big.NewFloat(1))

	fmt.Println(q.BitLen(), sigmaI.BitLen(), sigma)

	sigma1 := new(big.Float).Mul(sigma, boundF)
	sigma1.Mul(sigma1, big.NewFloat(math.Sqrt(float64(2 * l))))
	sigma1I, _ := sigma1.Int(nil)
	sigma1.SetInt(sigma1I)
	sigma2 := new(big.Float).Mul(sigma, big.NewFloat(math.Sqrt(2)))
	sigma3 := new(big.Float).Mul(sigma2, sigma2)
	sigma3.Mul(sigma3, big.NewFloat(float64(2 * n * l * sec)))
	sigma3.Add(sigma3, big.NewFloat(1))
	sigma3.Sqrt(sigma3)
	sigma3.Mul(sigma3, sigma1)
	sigma3I, _ := sigma3.Int(nil)
	sigma3.SetInt(sigma3I)
	fmt.Println(sigma1, sigma2, sigma3)

	sampler1, err := sample.NewNormalDouble(sigma1, uint(n), big.NewFloat(1))
	if err != nil {
		return nil, err
	}
	sampler2 := sample.NewNormalCumulative(sigma2, uint(n), true)
	sampler3, err := sample.NewNormalDouble(sigma3, uint(n), big.NewFloat(1))
	if err != nil {
		return nil, err
	}

	if !isPowOf2(n) {
		return nil, fmt.Errorf("security parameter n is not a power of 2")
	}

	randVec, err := data.NewRandomVector(n, sample.NewUniform(q))
	if err != nil {
		return nil, errors.Wrap(err, "cannot generate random polynomial")
	}

	return &RingLWE{
		Params: &RingLWEParams{
			L:     l,
			N:     n,
			Bound: bound,
			P:     p,
			Q:     q,
			Sigma: sigma,
			Sigma1: sigma1,
			Sigma2: sigma2,
			Sigma3: sigma3,
			A:     randVec,
		},
		Sampler1: sampler1,
		Sampler2: sampler2,
		Sampler3: sampler3,
	}, nil
}

// Calculates the center function t(x) = floor(x*q/p) % q for a matrix X.
func (s *RingLWE) center(X data.Matrix) data.Matrix {
	return X.Apply(func(x *big.Int) *big.Int {
		t := new(big.Int)
		t.Mul(x, s.Params.Q)
		t.Div(t, s.Params.P)
		t.Mod(t, s.Params.Q)

		return t
	})
}

// GenerateSecretKey generates a secret key for the scheme.
// The key is a matrix of l*n small elements sampled from
// Discrete Gaussian distribution.
//
// In case secret key could not be generated, it returns an error.
func (s *RingLWE) GenerateSecretKey() (data.Matrix, error) {
	return data.NewRandomMatrix(s.Params.L, s.Params.N, s.Sampler1)
}

// GeneratePublicKey accepts a master secret key SK and generates a
// corresponding master public key.
// Public key is a matrix of l*n elements.
// In case of a malformed secret key the function returns an error.
func (s *RingLWE) GeneratePublicKey(SK data.Matrix) (data.Matrix, error) {
	if !SK.CheckDims(s.Params.L, s.Params.N) {
		return nil, gofe.MalformedPubKey
	}
	// Generate noise matrix
	// Elements are sampled from the same distribution as the secret key S.
	E, err := data.NewRandomMatrix(s.Params.L, s.Params.N, s.Sampler1)
	if err != nil {
		return nil, errors.Wrap(err, "public key generation failed")
	}

	// Calculate public key PK row by row as PKi = (a * SKi + Ei) % q.
	// Multiplication and addition are in the ring of polynomials
	PK := make(data.Matrix, s.Params.L)
	for i := 0; i < PK.Rows(); i++ {
		pkI, _ := SK[i].MulAsPolyInRing(s.Params.A)
		pkI = pkI.Add(E[i])
		PK[i] = pkI
	}
	PK = PK.Mod(s.Params.Q)

	return PK, nil
}

// DeriveKey accepts input vector y and master secret key SK, and derives a
// functional encryption key.
// In case of malformed secret key or input vector that violates the
// configured bound, it returns an error.
func (s *RingLWE) DeriveKey(y data.Vector, SK data.Matrix) (data.Vector, error) {
	if err := y.CheckBound(s.Params.Bound); err != nil {
		return nil, err
	}
	if !SK.CheckDims(s.Params.L, s.Params.N) {
		return nil, gofe.MalformedSecKey
	}
	// Secret key is a linear combination of input vector y and master secret keys.
	SKTrans := SK.Transpose()
	skY, err := SKTrans.MulVec(y)
	if err != nil {
		return nil, gofe.MalformedInput
	}
	skY = skY.Mod(s.Params.Q)

	return skY, nil
}

// Encrypt encrypts matrix X using public key PK.
// It returns the resulting ciphertext matrix. In case of malformed
// public key or input matrix that violates the configured bound,
// it returns an error.
//
//The resulting ciphertext has dimensions (l + 1) * n.
func (s *RingLWE) Encrypt(X data.Matrix, PK data.Matrix) (data.Matrix, error) {
	if err := X.CheckBound(s.Params.Bound); err != nil {
		return nil, err
	}

	if !PK.CheckDims(s.Params.L, s.Params.N) {
		return nil, gofe.MalformedPubKey
	}
	if !X.CheckDims(s.Params.L, s.Params.N) {
		return nil, gofe.MalformedInput
	}

	// Create a small random vector r
	r, err := data.NewRandomVector(s.Params.N, s.Sampler2)
	if err != nil {
		return nil, errors.Wrap(err, "error in encrypt")
	}
	// Create noise matrix E to secure the encryption
	E, err := data.NewRandomMatrix(s.Params.L, s.Params.N, s.Sampler3)
	if err != nil {
		return nil, errors.Wrap(err, "error in encrypt")
	}
	// Calculate cipher CT row by row as CTi = (PKi * r + Ei) % q.
	// Multiplication and addition are in the ring of polynomials.
	CT0 := make(data.Matrix, s.Params.L)
	for i := 0; i < CT0.Rows(); i++ {
		CT0i, _ := PK[i].MulAsPolyInRing(r)
		CT0i = CT0i.Add(E[i])
		CT0[i] = CT0i
	}
	CT0 = CT0.Mod(s.Params.Q)

	// Include the message X in the encryption
	T := s.center(X)
	CT0, _ = CT0.Add(T)
	CT0 = CT0.Mod(s.Params.Q)

	// Construct the last row of the cipher
	ct1, _ := s.Params.A.MulAsPolyInRing(r)
	e, err := data.NewRandomVector(s.Params.N, s.Sampler2)
	if err != nil {
		return nil, errors.Wrap(err, "error in encrypt")
	}
	ct1 = ct1.Add(e)
	ct1 = ct1.Mod(s.Params.Q)

	return append(CT0, ct1), nil
}

// Decrypt accepts an encrypted matrix CT, secret key skY, and plaintext
// vector y, and returns a vector of inner products of X's rows and y.
// If decryption failed (for instance with input data that violates the
// configured bound or malformed ciphertext or keys), error is returned.
func (s *RingLWE) Decrypt(CT data.Matrix, skY, y data.Vector) (data.Vector, error) {
	if err := y.CheckBound(s.Params.Bound); err != nil {
		return nil, err
	}
	if len(skY) != s.Params.N {
		return nil, gofe.MalformedDecKey
	}
	if len(y) != s.Params.L {
		return nil, gofe.MalformedInput
	}

	if !CT.CheckDims(s.Params.L +1, s.Params.N) {
		return nil, gofe.MalformedCipher
	}
	CT0 := CT[:s.Params.L] // First l rows of cipher
	ct1 := CT[s.Params.L]  // Last row of cipher

	CT0Trans := CT0.Transpose()
	CT0TransMulY, _ := CT0Trans.MulVec(y)
	CT0TransMulY = CT0TransMulY.Mod(s.Params.Q)

	ct1MulSkY, _ := ct1.MulAsPolyInRing(skY)
	ct1MulSkY = ct1MulSkY.Apply(func(x *big.Int) *big.Int {
		return new(big.Int).Neg(x)
	})

	d := CT0TransMulY.Add(ct1MulSkY)
	d = d.Mod(s.Params.Q)
	halfQ := new(big.Int).Div(s.Params.Q, big.NewInt(2))

	d = d.Apply(func(x *big.Int) *big.Int {
		if x.Cmp(halfQ) == 1 {
			x.Sub(x, s.Params.Q)
		}
		x.Mul(x, s.Params.P)
		x.Add(x, halfQ)
		x.Div(x, s.Params.Q)

		return x
	})

	return d, nil
}

func isPowOf2(x int) bool {
	return x&(x-1) == 0
}
