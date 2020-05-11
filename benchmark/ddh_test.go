package benchmark_test

import (
	"math/big"
	"testing"

	"os"
	"strconv"
	"time"

	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/innerprod/fullysec"
	"github.com/fentec-project/gofe/sample"
	"fmt"
)

// paramBounds holds the boundaries for acceptable mean
// and variance values.
type innerprodParams struct {
	l     int
	bound *big.Int
}

var params = []innerprodParams{
	{l: 1, bound: big.NewInt(1000)},
	{l: 5, bound: big.NewInt(1000)},
	{l: 10, bound: big.NewInt(1000)},
	{l: 20, bound: big.NewInt(1000)},
	{l: 50, bound: big.NewInt(1000)},
	{l: 100, bound: big.NewInt(1000)},
	{l: 200, bound: big.NewInt(1000)},
	{l: 10, bound: big.NewInt(10)},
	{l: 10, bound: big.NewInt(100)},
	{l: 10, bound: big.NewInt(10000)},
	//{l: 10, bound: big.NewInt(100000),},
}

var maxN = 100

func genRandVec() ([]data.Matrix, []data.Matrix) {
	x := make([]data.Matrix, len(params))
	y := make([]data.Matrix, len(params))

	for i := 0; i < len(params); i++ {
		var sampler = sample.NewUniformRange(new(big.Int).Add(new(big.Int).Neg(params[i].bound), big.NewInt(1)), params[i].bound)
		x[i], _ = data.NewRandomMatrix(maxN, params[i].l, sampler)
		y[i], _ = data.NewRandomMatrix(maxN, params[i].l, sampler)
	}
	return x, y
}

var X, Y = genRandVec()

func TestBenchDam(t *testing.T) {
	f, err := os.Create("benchmark_results_damgard.txt")
	if err != nil {
		t.Fatalf("Error: %v", err)

	}

	for j, par := range params {
		y := Y[j]
		x := X[j]
		fmt.Println(y, x)
		var err error
		schemes := make([]*fullysec.Damgard, maxN)
		masterSecKey := make([]*fullysec.DamgardSecKey, maxN)
		masterPubKey := make([]data.Vector, maxN)
		key := make([]*fullysec.DamgardDerivedKey, maxN)
		ciphertext := make([]data.Vector, maxN)

		//var xy *big.Int
		var res = make([]int64, maxN)
		var start time.Time
		var elapsed time.Duration

		for i := 0; i < maxN; i++ {
			start = time.Now()
			schemes[i], err = fullysec.NewDamgardPrecomp(par.l, 2048, par.bound)
			elapsed = time.Since(start)
			res[i] = elapsed.Microseconds()
			if err != nil {
				t.Fatalf("Error: %v", err)
			}

		}
		f.Write([]byte("S " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(avgSlice(res)) + "\n"))

		for i := 0; i < maxN; i++ {
			start = time.Now()
			masterSecKey[i], masterPubKey[i], err = schemes[i].GenerateMasterKeys()
			elapsed = time.Since(start)
			res[i] = elapsed.Microseconds()
			if err != nil {
				t.Fatalf("Error: %v", err)
			}
		}
		f.Write([]byte("K " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(avgSlice(res)) + "\n"))

		for i := 0; i < maxN; i++ {

			start = time.Now()
			key[i], err = schemes[i].DeriveKey(masterSecKey[i], y[i])
			elapsed = time.Since(start)
			res[i] = elapsed.Microseconds()

			if err != nil {
				t.Fatalf("Error: %v", err)
			}
		}

		f.Write([]byte("F " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(avgSlice(res)) + "\n"))

		for i := 0; i < maxN; i++ {

			start = time.Now()
			ciphertext[i], err = schemes[i].Encrypt(x[i], masterPubKey[i])
			elapsed = time.Since(start)
			res[i] = elapsed.Microseconds()

			if err != nil {
				t.Fatalf("Error: %v", err)
			}
		}
		f.Write([]byte("E " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(avgSlice(res)) + "\n"))

		for i := 0; i < maxN; i++ {
			start = time.Now()
			_, err = schemes[i].Decrypt(ciphertext[i], key[i], y[i])
			elapsed = time.Since(start)
			res[i] = elapsed.Microseconds()

			if err != nil {
				t.Fatalf("Error: %v", err)
			}
		}

		f.Write([]byte("D " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(avgSlice(res)) + "\n"))

	}
	f.Close()
}

func TestBenchEC(t *testing.T) {
	f, err := os.Create("benchmark_results_ec.txt")
	if err != nil {
		t.Fatalf("Error: %v", err)

	}

	for j, par := range params {
		y := Y[j]
		x := X[j]
		//xyCheck, _ := x[0].Dot(y[1])
		fmt.Println(y, x)

		var err error
		scheme := make([]*fullysec.ECIPE, maxN)
		key := make([]*fullysec.ECIPEDerivedKey, maxN)
		ciphertext := make([]data.VectorEC, maxN)

		masterSecKey := make([]*fullysec.ECIPESecKey, maxN)
		masterPubKey := make([]data.VectorEC, maxN)

		var res = make([]int64, maxN)
		var start time.Time
		var elapsed time.Duration
		//var xy *big.Int
		for i := 0; i < maxN; i++ {
			start = time.Now()

			scheme[i], err = fullysec.NewECIPE(par.l, par.bound)
			elapsed = time.Since(start)
			res[i] = elapsed.Microseconds()
			if err != nil {
				t.Fatalf("Error: %v", err)

			}
		}
		f.Write([]byte("S " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(avgSlice(res)) + "\n"))

		for i := 0; i < maxN; i++ {
			start = time.Now()

			masterSecKey[i], masterPubKey[i], err = scheme[i].GenerateKeys()
			elapsed = time.Since(start)
			res[i] = elapsed.Microseconds()
			if err != nil {
				t.Fatalf("Error: %v", err)
			}
		}

		f.Write([]byte("K " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(avgSlice(res)) + "\n"))

		for i := 0; i < maxN; i++ {

			start = time.Now()
			key[i], err = scheme[i].DeriveKey(masterSecKey[i], y[i])
			elapsed = time.Since(start)
			res[i] = elapsed.Microseconds()

			if err != nil {
				t.Fatalf("Error: %v", err)
			}
		}

		f.Write([]byte("F " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(avgSlice(res)) + "\n"))

		for i := 0; i < maxN; i++ {

			start = time.Now()
			ciphertext[i], err = scheme[i].Encrypt(x[i], masterPubKey[i])
			elapsed = time.Since(start)
			res[i] = elapsed.Microseconds()

			if err != nil {
				t.Fatalf("Error: %v", err)
			}
		}
		f.Write([]byte("E " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(avgSlice(res)) + "\n"))

		for i := 0; i < maxN; i++ {
			start = time.Now()
			_, err = scheme[i].Decrypt(ciphertext[i], key[i], y[i])
			elapsed = time.Since(start)
			res[i] = elapsed.Microseconds()

			if err != nil {
				t.Fatalf("Error: %v", err)
			}
		}

		f.Write([]byte("D " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(avgSlice(res)) + "\n"))

		//assert.Equal(t, xy.Cmp(xyCheck), 0, "obtained incorrect inner product")
	}
	f.Close()
}

func avgSlice(x []int64) int {

	total := int64(0)
	for _, valuex := range x {
		total += valuex
	}

	return int(total / int64(len(x)))
}
