package benchmark_test

import (
	"testing"
	"math/big"

	"github.com/fentec-project/gofe/innerprod/fullysec"
	"os"
	"strconv"
	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/sample"
)

// paramBounds holds the boundaries for acceptable mean
// and variance values.
type innerprodParams struct {
	l int
	bound *big.Int
}

var params = []innerprodParams{
	{l: 1, bound: big.NewInt(1000),},
	{l: 5, bound: big.NewInt(1000),},
	{l: 10, bound: big.NewInt(1000),},
	{l: 20, bound: big.NewInt(1000),},
	{l: 50, bound: big.NewInt(1000),},
	{l: 100, bound: big.NewInt(1000),},
	{l: 200, bound: big.NewInt(1000),},
	{l: 10, bound: big.NewInt(10),},
	{l: 10, bound: big.NewInt(100),},
	{l: 10, bound: big.NewInt(10000),},
	{l: 10, bound: big.NewInt(100000),},
}

var maxN = 1

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
		//sampler := sample.NewUniformRange(new(big.Int).Add(new(big.Int).Neg(par.bound), big.NewInt(1)), par.bound)

		//y, _ := data.NewRandomMatrix(maxN, par.l, sampler)
		//x, _ := data.NewRandomMatrix(maxN, par.l, sampler)
		y := Y[j]
		x := X[j]
		//xyCheck, _ := x[0].Dot(y[1])

		var err error
		var damgard *fullysec.Damgard
		var masterSecKey *fullysec.DamgardSecKey
		var masterPubKey data.Vector
		key := make([]*fullysec.DamgardDerivedKey, maxN)
		ciphertext := make([]data.Vector, maxN)

		//var xy *big.Int
		var res testing.BenchmarkResult
		res = testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				damgard, err = fullysec.NewDamgardPrecomp(par.l, 2048, par.bound)
				if err != nil {
					t.Fatalf("Error: %v", err)

				}
			}
		})
		f.Write([]byte("S " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(int(res.NsPerOp())) + " " + strconv.Itoa(int(res.N)) + "\n"))

		res = testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				masterSecKey, masterPubKey, err = damgard.GenerateMasterKeys()
				if err != nil {
					t.Fatalf("Error: %v", err)
				}
			}
		})
		f.Write([]byte("K " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(int(res.NsPerOp())) + " " + strconv.Itoa(int(res.N)) + "\n"))


		res = testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if i < maxN {
					key[i], err = damgard.DeriveKey(masterSecKey, y[i])
				} else {
					_, err = damgard.DeriveKey(masterSecKey, y[i%maxN])
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
				if i < maxN {
					ciphertext[i], err = damgard.Encrypt(x[i], masterPubKey)
				} else {
					_, err = damgard.Encrypt(x[i%maxN], masterPubKey)
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
				_, err = damgard.Decrypt(ciphertext[i%maxN], key[i%maxN], y[i%maxN])
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


func TestBenchEC(t *testing.T) {
	f, err := os.Create("benchmark_results_ec.txt")
	if err != nil {
		t.Fatalf("Error: %v", err)

	}

	for j, par := range params {
		//sampler := sample.NewUniformRange(new(big.Int).Add(new(big.Int).Neg(par.bound), big.NewInt(1)), par.bound)

		//y, _ := data.NewRandomMatrix(maxN, par.l, sampler)
		//x, _ := data.NewRandomMatrix(maxN, par.l, sampler)
		//y := data.NewConstantMatrix(maxN, par.l, big.NewInt(1))
		//x := data.NewConstantMatrix(maxN, par.l, big.NewInt(1))
		y := Y[j]
		x := X[j]
		//xyCheck, _ := x[0].Dot(y[1])

		var err error
		var scheme *fullysec.ECIPE
		var masterSecKey *fullysec.ECIPESecKey
		var masterPubKey data.VectorEC
		key := make([]*fullysec.ECIPEDerivedKey, maxN)
		ciphertext := make([]data.VectorEC, maxN)

		//var xy *big.Int
		var res testing.BenchmarkResult
		res = testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				scheme, err = fullysec.NewECIPE(par.l, par.bound)
				if err != nil {
					t.Fatalf("Error: %v", err)

				}
			}
		})
		f.Write([]byte("S " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(int(res.NsPerOp())) + " " + strconv.Itoa(int(res.N)) + "\n"))

		res = testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				masterSecKey, masterPubKey, err = scheme.GenerateKeys()
				if err != nil {
					t.Fatalf("Error: %v", err)
				}
			}
		})
		f.Write([]byte("K " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(int(res.NsPerOp())) + " " + strconv.Itoa(int(res.N)) + "\n"))

		res = testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if i < maxN {
					key[i], err = scheme.DeriveKey(masterSecKey, y[i])
				} else {
					_, err = scheme.DeriveKey(masterSecKey, y[i%maxN])
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
				if i < maxN {
					ciphertext[i], err = scheme.Encrypt(x[i], masterPubKey)
				} else {
					_, err = scheme.Encrypt(x[i%maxN], masterPubKey)
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
				_, err = scheme.Decrypt(ciphertext[i%maxN], key[i%maxN], y[i%maxN])
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

