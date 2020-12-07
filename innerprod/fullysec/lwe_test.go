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
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/innerprod/fullysec"
	"github.com/fentec-project/gofe/sample"
	"github.com/stretchr/testify/assert"
)

func TestFullySec_LWE(t *testing.T) {
	l := 64
	n := 150

	boundX := big.NewInt(1) // maximal size of the entry of the message
	boundY := big.NewInt(1) // maximal size of the entry of the other operand for inner product

	x, y, xy := testVectorData(l, boundX, boundY)
	emptyVec := data.Vector{}
	emptyMat := data.Matrix{}

	fsLWE, err := fullysec.NewLWE(l, n, boundX, boundY)
	assert.NoError(t, err)

	start := time.Now()
	Z, err := fsLWE.GenerateSecretKey()
	//assert.NoError(t, err)

	//_, err = fsLWE.GeneratePublicKey(emptyMat)
	//assert.Error(t, err)
	U, err := fsLWE.GeneratePublicKey(Z)
	elapsed := time.Since(start)
	fmt.Println("keygen", elapsed.Milliseconds())

	assert.NoError(t, err)

	_, err = fsLWE.DeriveKey(emptyVec, Z)
	assert.Error(t, err)
	_, err = fsLWE.DeriveKey(y, emptyMat)
	assert.Error(t, err)
	_, err = fsLWE.DeriveKey(y.MulScalar(big.NewInt(10000)), emptyMat)
	assert.Error(t, err) // boundary violation
	start = time.Now()
	zY, err := fsLWE.DeriveKey(y, Z)
	elapsed = time.Since(start)
	fmt.Println("derivekey", elapsed.Milliseconds())
	assert.NoError(t, err)

	_, err = fsLWE.Encrypt(emptyVec, U)
	assert.Error(t, err)
	_, err = fsLWE.Encrypt(x, emptyMat)
	assert.Error(t, err)
	_, err = fsLWE.Encrypt(x.MulScalar(big.NewInt(10000)), U)
	assert.Error(t, err) // boundary violation

	start = time.Now()

	cipher, err := fsLWE.Encrypt(x, U)
	elapsed = time.Since(start)
	fmt.Println("encrypt", elapsed.Milliseconds())
	assert.NoError(t, err)

	_, err = fsLWE.Decrypt(emptyVec, zY, y)
	assert.Error(t, err)
	_, err = fsLWE.Decrypt(cipher, emptyVec, y)
	assert.Error(t, err)
	_, err = fsLWE.Decrypt(cipher, zY, emptyVec)
	assert.Error(t, err)
	_, err = fsLWE.Decrypt(cipher, zY, y.MulScalar(big.NewInt(10000)))
	assert.Error(t, err) // boundary violation
	start = time.Now()
	xyDecrypted, err := fsLWE.Decrypt(cipher, zY, y)
	elapsed = time.Since(start)
	fmt.Println("decrypt", elapsed.Milliseconds())
	assert.NoError(t, err)
	assert.Equal(t, xy.Cmp(xyDecrypted), 0, "obtained incorrect inner product")
}

// testVectorData returns random vectors x, y, each containing
// elements up to the respective bound.
// It also returns the dot product of the vectors.
func testVectorData(len int, boundX, boundY *big.Int) (data.Vector, data.Vector, *big.Int) {
	samplerX := sample.NewUniformRange(new(big.Int).Neg(boundX), boundX)
	samplerY := sample.NewUniformRange(new(big.Int).Neg(boundY), boundY)
	x, _ := data.NewRandomVector(len, samplerX)
	y, _ := data.NewRandomVector(len, samplerY)
	xy, _ := x.Dot(y)

	return x, y, xy
}
