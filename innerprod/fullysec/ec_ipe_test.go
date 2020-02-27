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

package fullysec_test

import (
	"testing"

	"math/big"
	"github.com/fentec-project/gofe/innerprod/fullysec"
	"github.com/fentec-project/gofe/sample"
	"github.com/fentec-project/gofe/data"
	"github.com/stretchr/testify/assert"
)


func TestFullySec_ec_ipe(t *testing.T) {
	// choose the parameters for the encryption and build the scheme
	l := 1000
	bound := big.NewInt(1024)
	ecipe, err := fullysec.NewECIPE(l, bound)
	if err != nil {
		t.Fatalf("Error during scheme creation: %v", err)
	}

	// generate master secret key and public key
	masterSecKey, masterPubKey, err := ecipe.GenerateKeys()
	if err != nil {
		t.Fatalf("Error during keys generation: %v", err)
	}

	// sample an inner product vector y and derive a functional key for vector y
	sampler := sample.NewUniformRange(new(big.Int).Add(new(big.Int).Neg(bound), big.NewInt(1)), bound)
	y, err := data.NewRandomVector(l, sampler)
	if err != nil {
		t.Fatalf("Error during random generation: %v", err)
	}
	key, err := ecipe.DeriveKey(masterSecKey, y)
	if err != nil {
		t.Fatalf("Error during key derivation: %v", err)
	}

	// sample a vector that will be encrypted
	x, err := data.NewRandomVector(l, sampler)
	if err != nil {
		t.Fatalf("Error during random generation: %v", err)
	}

	// simulate the instantiation of encryptor that encrypts x with public key
	encryptor := fullysec.NewECIPEFromParams(ecipe.Params)
	ciphertext, err := encryptor.Encrypt(x, masterPubKey)
	if err != nil {
		t.Fatalf("Error during encryption: %v", err)
	}

	// simulate a decryptor that decrypts the inner-product
	// using the derived FE key
	decryptor := fullysec.NewECIPEFromParams(ecipe.Params)
	xy, err := decryptor.Decrypt(ciphertext, key, y)
	if err != nil {
		t.Fatalf("Error during decryption: %v", err)
	}

	// check the correctness of the result
	xyCheck, err := x.Dot(y)
	if err != nil {
		t.Fatalf("Error during inner product calculation")
	}
	assert.Equal(t, xy.Cmp(xyCheck), 0, "obtained incorrect inner product")
}
