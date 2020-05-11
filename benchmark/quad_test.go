package benchmark_test

import (
	"math/big"
	"os"
	"strconv"
	"testing"

	"time"

	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/quadratic"
	"github.com/fentec-project/gofe/sample"
)

// paramBounds holds the boundaries for acceptable mean
// and variance values.
type quadParams struct {
	l     int
	bound *big.Int
}

var paramsQ = []quadParams{
	{l: 1, bound: big.NewInt(100)},
	{l: 2, bound: big.NewInt(100)},
	{l: 5, bound: big.NewInt(100)},
	{l: 10, bound: big.NewInt(100)},
	{l: 20, bound: big.NewInt(100)},
	{l: 50, bound: big.NewInt(100)},
	////{l: 100, bound: big.NewInt(1000),},
	////{l: 200, bound: big.NewInt(1000),},
	{l: 10, bound: big.NewInt(10)},
	{l: 10, bound: big.NewInt(20)},
	{l: 10, bound: big.NewInt(50)},
	//{l: 10, bound: big.NewInt(100),},
	{l: 10, bound: big.NewInt(200)},
	{l: 10, bound: big.NewInt(500)},
	{l: 10, bound: big.NewInt(1000)},
	//{l: 10, bound: big.NewInt(2000)},
	//{l: 10, bound: big.NewInt(100000),},
}

var maxnQ = 100

func genRandVecQ() ([]data.Matrix, []data.Matrix, [][]data.Matrix) {
	x := make([]data.Matrix, len(paramsQ))
	y := make([]data.Matrix, len(paramsQ))
	f := make([][]data.Matrix, len(paramsQ))

	for i := 0; i < len(paramsQ); i++ {
		var sampler = sample.NewUniformRange(new(big.Int).Add(new(big.Int).Neg(paramsQ[i].bound), big.NewInt(1)), paramsQ[i].bound)
		x[i], _ = data.NewRandomMatrix(maxnQ, paramsQ[i].l, sampler)
		y[i], _ = data.NewRandomMatrix(maxnQ, paramsQ[i].l, sampler)
		f[i] = make([]data.Matrix, maxnQ)
		for j := 0; j < maxnQ; j++ {
			f[i][j], _ = data.NewRandomMatrix(paramsQ[i].l, paramsQ[i].l, sampler)
		}
	}
	return x, y, f
}

var Xq, Yq, Fq = genRandVecQ()

func TestBenchSGP(t *testing.T) {
	f, err := os.Create("benchmark_results_sgp.txt")
	if err != nil {
		t.Fatalf("Error: %v", err)

	}

	for j, par := range paramsQ {
		y := Yq[j]
		x := Xq[j]
		ff := Fq[j]

		var err error
		key := make([]*bn256.G2, maxnQ)
		ciphertext := make([]*quadratic.SGPCipher, maxnQ)

		scheme := make([]*quadratic.SGP, maxnQ)
		masterSecKey := make([]*quadratic.SGPSecKey, maxnQ)

		//var xy *big.Int
		var res = make([]int64, maxnQ)
		var start time.Time
		var elapsed time.Duration

		for i := 0; i < maxnQ; i++ {
			start = time.Now()
			scheme[i] = quadratic.NewSGP(par.l, par.bound)
			elapsed = time.Since(start)
			res[i] = elapsed.Microseconds()

		}
		f.Write([]byte("S " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(avgSlice(res)) + "\n"))

		for i := 0; i < maxnQ; i++ {
			start = time.Now()
			masterSecKey[i], err = scheme[i].GenerateMasterKey()
			elapsed = time.Since(start)
			res[i] = elapsed.Microseconds()
			if err != nil {
				t.Fatalf("Error: %v", err)
			}
		}
		f.Write([]byte("K " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(avgSlice(res)) + "\n"))

		for i := 0; i < maxnQ; i++ {

			start = time.Now()
			key[i], err = scheme[i].DeriveKey(masterSecKey[i], ff[i])
			elapsed = time.Since(start)
			res[i] = elapsed.Microseconds()

			if err != nil {
				t.Fatalf("Error: %v", err)
			}
		}

		f.Write([]byte("F " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(avgSlice(res)) + "\n"))

		for i := 0; i < maxnQ; i++ {

			start = time.Now()
			ciphertext[i], err = scheme[i].Encrypt(x[i], y[i], masterSecKey[i])
			elapsed = time.Since(start)
			res[i] = elapsed.Microseconds()

			if err != nil {
				t.Fatalf("Error: %v", err)
			}
		}
		f.Write([]byte("E " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(avgSlice(res)) + "\n"))

		for i := 0; i < maxnQ; i++ {
			start = time.Now()
			_, err = scheme[i].Decrypt(ciphertext[i], key[i], ff[i])
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

func TestBenchQuad(t *testing.T) {
	f, err := os.Create("benchmark_results_quad.txt")
	if err != nil {
		t.Fatalf("Error: %v", err)

	}

	for j, par := range paramsQ {
		y := Yq[j]
		x := Xq[j]
		ff := Fq[j]

		var err error
		masterSecKey := make([]*quadratic.QuadSecKey, maxnQ)
		pubKey := make([]*quadratic.QuadPubKey, maxnQ)
		key := make([]data.VectorG2, maxnQ)
		ciphertext := make([]*quadratic.QuadCipher, maxnQ)

		scheme := make([]*quadratic.Quad, maxnQ)

		//var xy *big.Int
		var res = make([]int64, maxnQ)
		var start time.Time
		var elapsed time.Duration

		for i := 0; i < maxnQ; i++ {
			start = time.Now()
			scheme[i], err = quadratic.NewQuad(par.l, par.l, par.bound)
			elapsed = time.Since(start)
			res[i] = elapsed.Microseconds()
			if err != nil {
				t.Fatalf("Error: %v", err)
			}

		}
		f.Write([]byte("S " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(avgSlice(res)) + "\n"))

		for i := 0; i < maxnQ; i++ {
			start = time.Now()
			pubKey[i], masterSecKey[i], err = scheme[i].GenerateKeys()
			elapsed = time.Since(start)
			res[i] = elapsed.Microseconds()
			if err != nil {
				t.Fatalf("Error: %v", err)
			}
		}
		f.Write([]byte("K " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(avgSlice(res)) + "\n"))

		for i := 0; i < maxnQ; i++ {

			start = time.Now()
			key[i], err = scheme[i].DeriveKey(masterSecKey[i], ff[i])
			elapsed = time.Since(start)
			res[i] = elapsed.Microseconds()

			if err != nil {
				t.Fatalf("Error: %v", err)
			}
		}

		f.Write([]byte("F " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(avgSlice(res)) + "\n"))

		for i := 0; i < maxnQ; i++ {

			start = time.Now()
			ciphertext[i], err = scheme[i].Encrypt(x[i], y[i], pubKey[i])
			elapsed = time.Since(start)
			res[i] = elapsed.Microseconds()

			if err != nil {
				t.Fatalf("Error: %v", err)
			}
		}
		f.Write([]byte("E " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(avgSlice(res)) + "\n"))

		for i := 0; i < maxnQ; i++ {
			start = time.Now()
			_, err = scheme[i].Decrypt(ciphertext[i], key[i], ff[i])
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
