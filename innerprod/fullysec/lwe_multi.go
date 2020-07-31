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
	"crypto/rand"
	"fmt"
	"math"
	"math/big"

	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/sample"
)

// PaillierMulti represents a multi input variant of the
// underlying Paillier scheme based on
// Abdalla, Catalano, Fiore, Gay, and Ursu:
// "Multi-Input Functional Encryption for Inner Products:
// Function-Hiding Realizations and Constructions without Pairings".
// The participants in the scheme are clients and a central authority.
// The central authority generates keys for each client so that client i
// encrypts vector x_i. The scheme allows the central authority to
// generate a key_Y, depending on a matrix Y with rows y_i, so that
// given key_y and the ciphertext the decryptor can compute value
// Σ_i <x_i, y_i> (sum of dot products).

// PaillierMulti is a struct in PaillierMulti scheme, that holds
// all the shared parameters, and can represent the central authority
// or the decryptor.
type LWEMulti struct {
	NumClients int
	BoundX      *big.Int
	BoundY      *big.Int
	*LWE
}

// DamgardMultiClient represents a single client for the LWEMulti scheme.
type LWEMultiClient struct {
	BoundX      *big.Int
	BoundY      *big.Int
	*LWE
}

// NewLWEMulti configures a new instance of the scheme.
// It accepts the number of clients, the length of
// input vectors l, security parameter lambda (for number of
// bits of security the bit length of primes p and q to be generated
// (the scheme is operating in the Z_{(pq)^2} group), and a bound by
// which coordinates of input vectors are bounded. It generates all
//the remaining parameters to be shared.
//
// It returns an error in case the underlying LWE scheme
// instances could not be properly instantiated.
func NewLWEMulti(numClients, l, n int, boundX, boundY *big.Int) (*LWEMulti, error) {
	//var newBoundX *big.Int
	//newBoundX = nil
	//if boundX != nil && boundY != nil {
	//	newBoundX = new(big.Int).Mul(boundX, big.NewInt(3))
	//}

	//
	//lwe, err := NewLWE(l, n, newBoundX, boundY)
	//if err != nil {
	//	return nil, err
	//}

	//// K = 2 * l * boundX * boundY
	//K := new(big.Int).Mul(boundX, boundY)
	//K.Mul(K, big.NewInt(int64(l*2)))
	////K.Mul(boundX, big.NewInt(int64(numClients*l)))

	K := new(big.Int).Set(boundX)
	kF := new(big.Float).SetInt(K)
	SquaredF := new(big.Float).Mul(kF, kF)
	fmt.Println("k", K)
	nF := float64(n)

	nBitsQ := 1
	var sigma, sigma1, sigma2 *big.Float
	var lSigma1, lSigma2 *big.Int
	// parameters for the scheme are given as a set of requirements in the paper
	// hence we search for such parameters iteratively
	for i := 1; true; i++ {
		//assuming that the final q will have at most i bits we calculate a bound
		boundMF := float64(n * i)
		// tmp values
		log2M := math.Log2(boundMF)
		sqrtNLogM := math.Sqrt(nF * log2M)

		max := new(big.Float)
		if SquaredF.Cmp(big.NewFloat(boundMF)) == 1 {
			max.SetFloat64(boundMF)
		} else {
			max.Set(SquaredF)
		}

		sqrtMax := new(big.Float).Sqrt(max)

		sigma1 = new(big.Float).Mul(big.NewFloat(sqrtNLogM), sqrtMax)
		// to sample with NormalDoubleConstant sigmaQ must be
		// a multiple of sample.SigmaCDT = sqrt(1/2ln(2)), hence we make
		// it such
		lSigma1F := new(big.Float).Quo(sigma1, sample.SigmaCDT)
		lSigma1, _ = lSigma1F.Int(nil)
		sigma1.Mul(sample.SigmaCDT, lSigma1F)

		// tmp values
		nPow3 := math.Pow(nF, 3)
		powSqrtLogM5 := math.Pow(math.Sqrt(log2M), 5)
		mulVal := math.Sqrt(nF) * nPow3 * powSqrtLogM5 * math.Sqrt(boundMF)
		sigma2 = new(big.Float).Mul(big.NewFloat(mulVal), max)
		// to sample with NormalDoubleConstant sigmaQ must be
		// a multiple of sample.SigmaCDT = sqrt(1/2ln(2)), hence we make
		// it such
		lSigma2F := new(big.Float).Quo(sigma2, sample.SigmaCDT)
		lSigma2, _ = lSigma2F.Int(nil)
		sigma2.Mul(sample.SigmaCDT, lSigma2F)

		// tmp value
		sigma1Square := new(big.Float).Mul(sigma1, sigma1)
		sigma2Square := new(big.Float).Mul(sigma2, sigma2)

		bound2 := new(big.Float).Add(sigma1Square, sigma2Square)
		bound2.Sqrt(bound2)
		bound2.Mul(bound2, big.NewFloat(math.Sqrt(math.Log2(nF))))

		sigma = new(big.Float).Quo(big.NewFloat(1), SquaredF)
		sigma.Quo(sigma, bound2)
		sigma.Quo(sigma, big.NewFloat(math.Sqrt(math.Log2(nF))))

		// assuming number of bits of q will be at least nBitsQ from the previous
		// iteration (this is always true) we calculate sigma prime
		nfPow6 := math.Pow(nF, 6)
		nBitsQPow2 := math.Pow(float64(nBitsQ), 2)
		sqrtLog2nFPow5 := math.Pow(math.Sqrt(math.Log(nF)), 5)
		//fmt.Println(sqrtLog2nFPow5, sigma)
		sigmaPrime := new(big.Float).Quo(sigma, kF)
		sigmaPrime.Quo(sigmaPrime, big.NewFloat(nfPow6*nBitsQPow2*sqrtLog2nFPow5))
		//fmt.Println(sigmaPrime)

		boundForQ := new(big.Float)
		boundForQ.Quo(big.NewFloat(math.Sqrt(math.Log(nF))), sigmaPrime)
		//fmt.Println(boundForQ)
		nBitsQ = boundForQ.MantExp(nil) + 1
		// check if the number of bits for q is greater than i as it was
		// assumed at the beginning of the iteration
		if nBitsQ < i {
			break
		}
		// in the next iteration the number of bits for q must be at least as
		// many as it was demanded in this iteration
		//i = nBitsQ
		//fmt.Println(nBitsQ)
	}
	// get q
	q, err := rand.Prime(rand.Reader, nBitsQ)
	if err != nil {
		return nil, err
	}
	fmt.Println(nBitsQ)
	m := int(1.01 * nF * float64(nBitsQ))

	// get sigmaQ
	qF := new(big.Float).SetInt(q)
	sigmaQ := new(big.Float).Mul(sigma, qF)
	// to sample with NormalDoubleConstant sigmaQ must be
	// a multiple of sample.SigmaCDT = sqrt(1/2ln(2)), hence we make
	// it such
	lSigmaQF := new(big.Float).Quo(sigmaQ, sample.SigmaCDT)
	lSigmaQ, _ := lSigmaQF.Int(nil)
	sigmaQ.Mul(sample.SigmaCDT, lSigmaQF)

	fmt.Println(sigmaQ, sigma1, sigma2)
	qDivK := new(big.Int).Div(q, K)
	fmt.Println(new(big.Float).SetInt(qDivK))
	fmt.Println(new(big.Float).Mul(sigma2, sigmaQ))
	fmt.Println(new(big.Float).Mul(new(big.Float).Mul(sigma2, sigmaQ), big.NewFloat(math.Sqrt(float64(numClients)) * math.Log(float64(n)))))


	randMat, err := data.NewRandomMatrix(m, n, sample.NewUniform(q))
	if err != nil {
		return nil, err
	}
	lwe := &LWE{
		Params: &LWEParams{
			L:       l,
			N:       n,
			M:       m,
			BoundX:  boundX,
			BoundY:  boundY,
			Q:       q,
			K:       K,
			SigmaQ:  sigmaQ,
			LSigmaQ: lSigmaQ,
			Sigma1:  sigma1,
			LSigma1: lSigma1,
			Sigma2:  sigma2,
			LSigma2: lSigma2,
			A:       randMat,
		},
	}



	// the bound of the underlying Damgard scheme is set to
	// the maximum value since the scheme will be used to encrypt
	// values summed with one time pad, thus arbitrary big
	lwe.Params.BoundX = lwe.Params.Q
	lwe.Params.BoundY = lwe.Params.Q

	return &LWEMulti{
		NumClients: numClients,
		BoundY:     boundY,
		BoundX:     boundX,
		LWE:        lwe,
	}, nil
}


// NewLWEMultiClientFromParams takes the bound and configuration parameters of an underlying
// LWE scheme instance, and instantiates a new LWEMultiClient.
//
// It returns a new LWEMultiClient instance.
func NewLWEMultiClientFromParams(params *LWEParams, boundX, boundY *big.Int) *LWEMultiClient {
	return &LWEMultiClient{
		BoundY: boundY,
		BoundX: boundX,
		LWE: &LWE{params},
	}
}

// NewLWEMultiFromParams takes the number of clients, bound and configuration
// parameters of an existing LWE scheme instance, and reconstructs
// the scheme with same configuration parameters.
//
// It returns a new LWEMulti instance.
func NewLWEMultiFromParams(numClients int, boundX, boundY *big.Int, params *LWEParams) *LWEMulti {
	return &LWEMulti{
		NumClients: numClients,
		BoundX: boundX,
		BoundY: boundY,
		LWE:    &LWE{params},
	}
}

// LWEMultiSecKeys is a struct containing keys and one time pads for all the clients in
// the LWE multi input scheme.
type LWEMultiSecKeys struct {
	Msk []data.Matrix
	Mpk []data.Matrix
	Otp data.Matrix
}

// GenerateMasterKeys generates keys and one time pads for all the clients.
//
// It returns an error in case values could not be generated.
func (dm *LWEMulti) GenerateMasterKeys() (*LWEMultiSecKeys, error) {
	multiMsk := make([]data.Matrix, dm.NumClients)
	multiMpk := make([]data.Matrix, dm.NumClients)
	multiOtp := make([]data.Vector, dm.NumClients)

	for i := 0; i < dm.NumClients; i++ {
		msk, err := dm.LWE.GenerateSecretKey()
		if err != nil {
			return nil, fmt.Errorf("error in master key generation")
		}
		multiMsk[i] = msk
		mpk, err := dm.LWE.GeneratePublicKey(msk)
		if err != nil {
			return nil, fmt.Errorf("error in master key generation")
		}
		multiMpk[i] = mpk

		otp, err := data.NewRandomVector(dm.Params.L, sample.NewUniform(dm.Params.Q))
		if err != nil {
			return nil, fmt.Errorf("error in random vector generation")
		}
		//otp := data.NewConstantVector(dm.Params.L, big.NewInt(0))

		multiOtp[i] = otp
	}
	secKeys := &LWEMultiSecKeys{
		Msk: multiMsk,
		Mpk: multiMpk,
		Otp: data.Matrix(multiOtp),
	}

	return secKeys, nil
}

// Encrypt generates a ciphertext from the input vector x
// with the provided public key of the underlying LWE scheme and
// one-time pad otp (which are a part of the secret key). It returns
// the ciphertext vector. If the encryption failed, error is returned.
func (e *LWEMultiClient) Encrypt(x data.Vector, pubKey data.Matrix, otp data.Vector) (data.Vector, error) {
	if e.BoundX != nil {
		if err := x.CheckBound(e.BoundX); err != nil {
			return nil, err
		}
	}

	xAddOtp := x.Add(otp)
	xAddOtp = xAddOtp.Mod(e.Params.Q)

	return e.LWE.Encrypt(xAddOtp, pubKey)
}

// LWEMultiDerivedKey is a functional encryption key for LWEMulti scheme.
type LWEMultiDerivedKey struct {
	Keys []data.Vector
	Z    *big.Int // Σ <u_i, y_i> where u_i is OTP key for i-th client
}

// DeriveKey takes master secret key and a matrix y comprised
// of input vectors, and returns the functional encryption key.
// In case the key could not be derived, it returns an error.
func (dm *LWEMulti) DeriveKey(secKey *LWEMultiSecKeys, y data.Matrix) (*LWEMultiDerivedKey, error) {
	if dm.BoundY != nil {
		if err := y.CheckBound(dm.BoundY); err != nil {
			return nil, err
		}
	}
	z, err := secKey.Otp.Dot(y)
	if err != nil {
		return nil, err
	}
	z.Mod(z, dm.Params.Q)

	derivedKeys := make([]data.Vector, dm.NumClients)
	for i := 0; i < dm.NumClients; i++ {
		derivedKey, err := dm.LWE.DeriveKey(y[i], secKey.Msk[i])
		if err != nil {
			return nil, err
		}
		derivedKeys[i] = derivedKey
	}

	//bla, _ := data.Matrix(derivedKeys).Transpose().MulVec(data.NewConstantVector(len(y), big.NewInt(1)))
	//fmt.Println(bla, z)
	return &LWEMultiDerivedKey{derivedKeys, z}, nil
}

// Decrypt accepts an array of ciphers, i.e. an array of encrypted vectors,
// functional encryption key, and a matrix y describing the inner-product.
// It returns the sum of inner products Σ_i <x_i, y_i>.
// If decryption failed, error is returned.
func (dm *LWEMulti) Decrypt(cipher []data.Vector, key *LWEMultiDerivedKey, y data.Matrix) (*big.Int, error) {
	if dm.BoundY != nil {
		if err := y.CheckBound(dm.BoundY); err != nil {
			return nil, err
		}
	}
	//
	//if len(zY) != s.Params.M {
	//	return nil, gofe.ErrMalformedDecKey
	//}
	//if len(y) != s.Params.L {
	//	return nil, gofe.ErrMalformedInput
	//}
	//
	//if len(cipher) != s.Params.M+s.Params.L {
	//	return nil, gofe.ErrMalformedCipher
	//}

	//c0 := cipher[:s.Params.M]
	//c1 := cipher[s.Params.M:]
	//yDotC1, _ := y.Dot(c1)
	//zYDotC0, _ := zY.Dot(c0)
	//
	//mu1 := new(big.Int).Sub(yDotC1, zYDotC0)
	//mu1.Mod(mu1, s.Params.Q)




	r := big.NewInt(0)
	for k := 0; k < dm.NumClients; k++ {
		c0 := cipher[k][:dm.Params.M]
		c1 := cipher[k][dm.Params.M:]
		yDotC1, _ := y[k].Dot(c1)
		zYDotC0, _ := key.Keys[k].Dot(c0)

		mu1 := new(big.Int).Sub(yDotC1, zYDotC0)
		mu1.Mod(mu1, dm.Params.Q)

		r.Add(r, mu1)
		r.Mod(r, dm.Params.Q)
	}

	qDivK := new(big.Int).Div(dm.Params.Q, dm.Params.K)
	z := new(big.Int).Mul(qDivK, key.Z)

	r.Sub(r, z)
	r.Mod(r, dm.Params.Q)


	//if r.Cmp(new(big.Int).Quo(dm.Params.Q, big.NewInt(2))) == 1 {
	//	r.Sub(r, dm.Params.Q)
	//}

	paramsKTimes2 := new(big.Int).Lsh(dm.Params.K, 1)
	//qDivK := new(big.Int).Div(s.Params.Q, s.Params.K)
	qDivKTimes2 := new(big.Int).Div(dm.Params.Q, paramsKTimes2)

	mu := new(big.Int).Add(r, qDivKTimes2)
	mu.Mod(mu, dm.Params.Q)

	mu.Div(mu, qDivK)

	return mu, nil
}
