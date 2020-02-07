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

package sample_test

import (
	"math/big"
	"testing"

	"github.com/fentec-project/gofe/sample"
	"time"
	"os"
	"strconv"
)

func TestNormalDoubleConstant(t *testing.T) {
	k := big.NewInt(50)
	sampler := sample.NewNormalDoubleConstant(k)

	f, err := os.Create("./times.txt")
	if err != nil {
		t.Fatalf("error : %v", err)
	}

		for i := 0; i < 1000000; i++ {
			start := time.Now()
			x, _ := sampler.Sample()
			t := time.Now()
			elapsed := t.Sub(start)
			//fmt.Println(x, elapsed.Nanoseconds())
			f.Write([]byte(x.String() + " " + strconv.Itoa(int(elapsed.Nanoseconds())) + "\n"))
		}

	f.Close()
}

func TestNormal_cdt(t *testing.T) {

	sampler := sample.NewNormalCDT()

	f, err := os.Create("./times.txt")
	if err != nil {
		t.Fatalf("error : %v", err)
	}

	for i := 0; i < 3000000; i++ {
		start := time.Now()
		x, _ := sampler.Sample()
		t := time.Now()
		elapsed := t.Sub(start)
		//fmt.Println(x, elapsed.Nanoseconds())
		f.Write([]byte(x.String() + " " + strconv.Itoa(int(elapsed.Nanoseconds())) + "\n"))
	}

	f.Close()
}

func TestNormalBenouli(t *testing.T) {

	l := big.NewFloat(16)
	lInv := new(big.Float).Quo(big.NewFloat(1), l)



	f, err := os.Create("./times_bernouli.txt")
	if err != nil {
		t.Fatalf("error : %v", err)
	}

	for i := 0; i < 1000000; i++ {
		start := time.Now()
		x := new(big.Int).SetInt64(int64(i % 10))
		sample.Bernoulli(x, lInv)
		t := time.Now()
		elapsed := t.Sub(start)
		//fmt.Println(x, elapsed.Nanoseconds())
		f.Write([]byte(x.String() + " " + strconv.Itoa(int(elapsed.Nanoseconds())) + "\n"))
	}

	f.Close()
}