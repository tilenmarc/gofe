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

package quadratic_test

import (
	"fmt"
	"github.com/fentec-project/bn256"
	"math/big"
	"testing"
	"time"

	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/quadratic"
	"github.com/fentec-project/gofe/sample"
	"github.com/stretchr/testify/assert"
)

func TestSGP(t *testing.T) {
	bound := big.NewInt(100)
	n := 20

	q := quadratic.NewSGP(n, bound)

	g1gen := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	g2gen := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	g := bn256.Pair(g1gen, g2gen)


	bound2 := new(big.Int).Exp(big.NewInt(2), big.NewInt(36), nil)
	q.GCalc = q.GCalc.WithBound(bound2).WithNeg()
	q.GCalc.Precompute(g)
	fmt.Println("started")

	num_repeats := 10

	params := [][2]int{{5, 100}, {20, 100}, {1, 500}, {1, 1000}, {20, 1000}}
	//params := [][2]int{{1, 500}, {1, 1}, {2, 1}}

	for _, e := range params {
		n = e[0]
		q.N = e[0]
		bound.SetInt64(1)
		sampler := sample.NewUniformRange(new(big.Int).Neg(bound), bound)

		avg := int64(0)
		fmt.Println("Evaluating...")
		for ii := 0; ii < num_repeats; ii++ {

			f, err := data.NewRandomMatrix(n, n, sampler)
			if err != nil {
				t.Fatalf("error when generating random matrix: %v", err)
			}

			msk, err := q.GenerateMasterKey()
			if err != nil {
				t.Fatalf("error when generating master keys: %v", err)
			}

			x, err := data.NewRandomVector(n, sampler)
			if err != nil {
				t.Fatalf("error when generating random vector: %v", err)
			}
			y, err := data.NewRandomVector(n, sampler)
			if err != nil {
				t.Fatalf("error when generating random vector: %v", err)
			}
			//x[0].Set(big.NewInt(-10))

			c, err := q.Encrypt(x, y, msk)
			if err != nil {
				t.Fatalf("error when encrypting: %v", err)
			}

			key, err := q.DeriveKey(msk, f)
			if err != nil {
				t.Fatalf("error when deriving key: %v", err)
			}

			check, err := f.MulXMatY(x, y)
			if err != nil {
				t.Fatalf("error when computing x*F*y: %v", err)
			}

			start := time.Now()
			dec, err := q.Decrypt(c, key, f)
			elapsed := time.Since(start)
			avg += elapsed.Milliseconds()
			//fmt.Println(dec)
			if err != nil {
				t.Fatalf("error when decrypting: %v", err)
			}

			assert.Equal(t, check, dec, "Decryption wrong")
		}

		avg = avg / int64(num_repeats)
		fmt.Println("result", e, avg)
	}
}
