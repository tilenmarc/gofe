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

package simple_test

import (
	"math/big"
	"testing"

	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/innerprod/simple"
	"github.com/fentec-project/gofe/sample"
	"github.com/stretchr/testify/assert"
)

func TestSimple_RingLWE(t *testing.T) {
	l := 5
	sec := 80
	b := big.NewInt(256)

	ringLWE, err := simple.NewRingLWE(l, sec, b)
	assert.NoError(t, err)

	sampler := sample.NewUniformRange(new(big.Int).Neg(new(big.Int).Add(b, big.NewInt(-1))), b)
	y, _ := data.NewRandomVector(l, sampler)
	X, _ := data.NewRandomMatrix(l, ringLWE.Params.N, sampler)
	xy, _ := X.Transpose().MulVec(y)
	emptyVec := data.Vector{}
	emptyMat := data.Matrix{}

	SK, err := ringLWE.GenerateSecretKey()
	assert.NoError(t, err)

	_, err = ringLWE.GeneratePublicKey(emptyMat)
	assert.Error(t, err)
	PK, err := ringLWE.GeneratePublicKey(SK)
	assert.NoError(t, err)

	_, err = ringLWE.DeriveKey(emptyVec, SK)
	assert.Error(t, err)
	_, err = ringLWE.DeriveKey(y, emptyMat)
	assert.Error(t, err)
	_, err = ringLWE.DeriveKey(y.MulScalar(b), SK)
	assert.Error(t, err) // boundary violated
	skY, err := ringLWE.DeriveKey(y, SK)
	assert.NoError(t, err)

	_, err = ringLWE.Encrypt(emptyMat, PK)
	assert.Error(t, err)
	_, err = ringLWE.Encrypt(X, emptyMat)
	assert.Error(t, err)
	_, err = ringLWE.Encrypt(X.MulScalar(b), PK)
	assert.Error(t, err) // boundary violated
	cipher, err := ringLWE.Encrypt(X, PK)
	assert.NoError(t, err)

	xyDecrypted, err := ringLWE.Decrypt(cipher, skY, y)
	assert.NoError(t, err)

	for i := 0; i < len(xyDecrypted); i++ {
		assert.Equal(t, xy[i].Cmp(xyDecrypted[i]), 0, "obtained incorrect inner product")
	}
}
