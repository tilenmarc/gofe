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
	"math/big"
	"testing"

	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/innerprod/fullysec"
	"github.com/fentec-project/gofe/sample"
	"os"
	"time"
	"strconv"
	"github.com/stretchr/testify/assert"

)

func TestFullySec_Paillier(t *testing.T) {
	l := 3
	boundX := new(big.Int).Exp(big.NewInt(2), big.NewInt(32), nil)
	boundY := new(big.Int).Exp(big.NewInt(2), big.NewInt(32), nil)
	//boundX := new(big.Int).SetInt64(5)
	//boundY := new(big.Int).SetInt64(5)

	samplerX := sample.NewUniformRange(new(big.Int).Add(new(big.Int).Neg(boundX), big.NewInt(1)), boundX)
	samplerY := sample.NewUniformRange(new(big.Int).Add(new(big.Int).Neg(boundX), big.NewInt(1)), boundY)
	bitLength := 512
	lambda := 128

	paillier, err := fullysec.NewPaillier(l, lambda, bitLength, boundX, boundY)
	if err != nil {
		t.Fatalf("Error during simple inner product creation: %v", err)
	}

	masterSecKey, masterPubKey, err := paillier.GenerateMasterKeys()
	if err != nil {
		t.Fatalf("Error during master key generation: %v", err)
	}

	y, err := data.NewRandomVector(l, samplerY)
	if err != nil {
		t.Fatalf("Error during random generation: %v", err)
	}

	key, err := paillier.DeriveKey(masterSecKey, y)
	if err != nil {
		t.Fatalf("Error during key derivation: %v", err)
	}



	// simulate the instantiation of encryptor (which should be given masterPubKey)
	encryptor := fullysec.NewPaillierFromParams(paillier.Params)



	list_x := data.NewConstantMatrix(20, 4, big.NewInt(1))
	for k := 0; k<20; k++ {
		list_x[k][0] = new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(k)), nil)
		list_x[k][1] = new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(k)), nil)
		list_x[k][2] = new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(k)), nil)
		list_x[k][3] = new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(k)), nil)
	}


	//list_x[1][0] = big.NewInt(10)
	//list_x[1][1] = big.NewInt(10)
	//list_x[1][2] = big.NewInt(10)
	//list_x[2][0] = big.NewInt(100)
	//list_x[2][1] = big.NewInt(100)
	//list_x[2][2] = big.NewInt(100)
	//list_x[3][0] = big.NewInt(1000)
	//list_x[3][1] = big.NewInt(1000)
	//list_x[3][2] = big.NewInt(1000)
	//list_x[4][0] = big.NewInt(10000)
	//list_x[4][1] = big.NewInt(10000)
	//list_x[4][2] = big.NewInt(10000)

	f, err := os.Create("./times_pailier.txt")
	if err != nil {
		t.Fatalf("error : %v", err)
	}

	var ciphertext data.Vector
	//ones := data.NewConstantVector(l, big.NewInt(1))
	for i := 0; i < 10000; i++ {
		z := list_x[i%20]
		x_norm, _ := z.Dot(z)

		start := time.Now()
		ciphertext, _ = encryptor.Encrypt(z, masterPubKey)
		t := time.Now()
		elapsed := t.Sub(start)
		//fmt.Println(x, elapsed.Nanoseconds())
		f.Write([]byte(x_norm.String() + " " + strconv.Itoa(int(elapsed.Microseconds())) + "\n"))
	}

	f.Close()

	x, err := data.NewRandomVector(l, samplerX)
	if err != nil {
		t.Fatalf("Error during random generation: %v", err)
	}

	ciphertext, err = encryptor.Encrypt(x, masterPubKey)
	if err != nil {
		t.Fatalf("Error during encryption: %v", err)
	}












	xy, err := paillier.Decrypt(ciphertext, key, y)
	if err != nil {
		t.Fatalf("Error during decryption")
	}

	xyCheck, err := x.Dot(y)
	if err != nil {
		t.Fatalf("Error during inner product calculation")
	}
	assert.Equal(t, xy.Cmp(xyCheck), 0, "Original and decrypted values should match")
}
