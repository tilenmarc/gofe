package benchmark_test

import (
	"testing"
	"math/big"
	"os"
	"strconv"
	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/sample"
	"github.com/fentec-project/gofe/quadratic"
	"github.com/fentec-project/bn256"
	"runtime"
)

// paramBounds holds the boundaries for acceptable mean
// and variance values.
type quadParams struct {
	l int
	bound *big.Int
}

var paramsQ = []quadParams{
	{l: 1, bound: big.NewInt(100),},
	{l: 2, bound: big.NewInt(100),},
	{l: 5, bound: big.NewInt(100),},
	{l: 10, bound: big.NewInt(100),},
	{l: 20, bound: big.NewInt(100),},
	{l: 50, bound: big.NewInt(100),},
	////{l: 100, bound: big.NewInt(1000),},
	////{l: 200, bound: big.NewInt(1000),},
	{l: 10, bound: big.NewInt(10),},
	{l: 10, bound: big.NewInt(20),},
	{l: 10, bound: big.NewInt(50),},
	//{l: 10, bound: big.NewInt(100),},
	{l: 10, bound: big.NewInt(200),},
	{l: 10, bound: big.NewInt(500),},
	{l: 10, bound: big.NewInt(1000),},
	{l: 10, bound: big.NewInt(2000),},
	//{l: 10, bound: big.NewInt(100000),},
}

var maxnQ = 1

func genRandVecQ() ([]data.Matrix, []data.Matrix, [][]data.Matrix) {
	runtime.GOMAXPROCS(2)
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
	dec := big.NewInt(0)
	sum := big.NewInt(0)
	for j, par := range paramsQ {
		//sampler := sample.NewUniformRange(new(big.Int).Add(new(big.Int).Neg(par.bound), big.NewInt(1)), par.bound)

		//y, _ := data.NewRandomMatrix(maxnQ, par.l, sampler)
		//x, _ := data.NewRandomMatrix(maxnQ, par.l, sampler)
		y := Yq[j]
		x := Xq[j]
		ff := Fq[j]
		//xyCheck, _ := x[0].Dot(y[1])

		var err error
		var damgard *quadratic.SGP
		var masterSecKey *quadratic.SGPSecKey
		key := make([]*bn256.G2, maxnQ)
		ciphertext := make([]*quadratic.SGPCipher, maxnQ)

		//var xy *big.Int
		var res testing.BenchmarkResult
		res = testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				damgard = quadratic.NewSGP(par.l, par.bound)
			}
		})
		f.Write([]byte("S " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(int(res.NsPerOp())) + " " + strconv.Itoa(int(res.N)) + "\n"))

		res = testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				masterSecKey, err = damgard.GenerateMasterKey()
				if err != nil {
					t.Fatalf("Error: %v", err)
				}
			}
		})
		f.Write([]byte("K " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(int(res.NsPerOp())) + " " + strconv.Itoa(int(res.N)) + "\n"))


		res = testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if i < maxnQ {
					key[i], err = damgard.DeriveKey(masterSecKey, ff[i])
				} else {
					_, err = damgard.DeriveKey(masterSecKey, ff[i%maxnQ])
				}
				if err != nil {
					t.Fatalf("Error: %v", err)
				}
			}
		})
		f.Write([]byte("F " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(int(res.NsPerOp())) + " " + strconv.Itoa(int(res.N)) + "\n"))


		res = testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if i < maxnQ {
					ciphertext[i], err = damgard.Encrypt(x[i], y[i], masterSecKey)
				} else {
					_, err = damgard.Encrypt(x[i%maxnQ], y[i%maxnQ], masterSecKey)
				}
				if err != nil {
					t.Fatalf("Error: %v", err)
				}
			}
		})
		f.Write([]byte("E " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(int(res.NsPerOp())) + " " + strconv.Itoa(int(res.N)) + "\n"))

		res = testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				dec, err = damgard.Decrypt(ciphertext[i%maxnQ], key[i%maxnQ], ff[i%maxnQ])
				if err != nil {
					t.Fatalf("Error: %v", err)
				}
				sum.Add(sum, dec)
			}

		})

		f.Write([]byte("D " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(int(res.NsPerOp())) + " " + strconv.Itoa(int(res.N)) + "\n"))

		//assert.Equal(t, xy.Cmp(xyCheck), 0, "obtained incorrect inner product")
	}
	f.Close()
}

func TestBenchQuad(t *testing.T) {
	f, err := os.Create("benchmark_results_quad.txt")
	if err != nil {
		t.Fatalf("Error: %v", err)

	}

	for j, par := range paramsQ {
		//sampler := sample.NewUniformRange(new(big.Int).Add(new(big.Int).Neg(par.bound), big.NewInt(1)), par.bound)

		//y, _ := data.NewRandomMatrix(maxnQ, par.l, sampler)
		//x, _ := data.NewRandomMatrix(maxnQ, par.l, sampler)
		y := Yq[j]
		x := Xq[j]
		ff := Fq[j]
		//xyCheck, _ := x[0].Dot(y[1])

		var err error
		var damgard *quadratic.Quad
		var masterSecKey *quadratic.QuadSecKey
		var pubKey *quadratic.QuadPubKey
		key := make([]data.VectorG2, maxnQ)
		ciphertext := make([]*quadratic.QuadCipher, maxnQ)

		//var xy *big.Int
		var res testing.BenchmarkResult
		res = testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				damgard, err = quadratic.NewQuad(par.l, par.l, par.bound)
			}
		})
		f.Write([]byte("S " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(int(res.NsPerOp())) + " " + strconv.Itoa(int(res.N)) + "\n"))

		res = testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				pubKey, masterSecKey, err = damgard.GenerateKeys()
				if err != nil {
					t.Fatalf("Error: %v", err)
				}
			}
		})
		f.Write([]byte("K " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(int(res.NsPerOp())) + " " + strconv.Itoa(int(res.N)) + "\n"))


		res = testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if i < maxnQ {
					key[i], err = damgard.DeriveKey(masterSecKey, ff[i])
				} else {
					_, err = damgard.DeriveKey(masterSecKey, ff[i%maxnQ])
				}
				if err != nil {
					t.Fatalf("Error: %v", err)
				}
			}
		})
		f.Write([]byte("F " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(int(res.NsPerOp())) + " " + strconv.Itoa(int(res.N)) + "\n"))


		res = testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if i < maxnQ {
					ciphertext[i], err = damgard.Encrypt(x[i], y[i], pubKey)
				} else {
					_, err = damgard.Encrypt(x[i%maxnQ], y[i%maxnQ], pubKey)
				}
				if err != nil {
					t.Fatalf("Error: %v", err)
				}
			}
		})
		f.Write([]byte("E " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(int(res.NsPerOp())) + " " + strconv.Itoa(int(res.N)) + "\n"))

		res = testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err = damgard.Decrypt(ciphertext[i%maxnQ], key[i%maxnQ], ff[i%maxnQ])
				if err != nil {
					t.Fatalf("Error: %v", err)
				}
			}

		})

		f.Write([]byte("D " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(int(res.NsPerOp())) + " " + strconv.Itoa(int(res.N)) + "\n"))

		//assert.Equal(t, xy.Cmp(xyCheck), 0, "obtained incorrect inner product")
	}
	f.Close()
}
