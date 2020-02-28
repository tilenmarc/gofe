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
	"github.com/fentec-project/gofe/innerprod/fullysec"
)

// paramBounds holds the boundaries for acceptable mean
// and variance values.
type decParams struct {
	l int
	bound *big.Int
}

var paramsD = []quadParams{
	{l: 1, bound: big.NewInt(1000),},
	{l: 5, bound: big.NewInt(1000),},
	//{l: 10, bound: big.NewInt(1000),},
	//{l: 20, bound: big.NewInt(1000),},
	//{l: 50, bound: big.NewInt(1000),},
	//{l: 100, bound: big.NewInt(1000),},
	//{l: 200, bound: big.NewInt(1000),},
	//{l: 10, bound: big.NewInt(10),},
	//{l: 10, bound: big.NewInt(100),},
	//{l: 10, bound: big.NewInt(1000),},
	//{l: 10, bound: big.NewInt(10000),},
	//{l: 10, bound: big.NewInt(100000),},
}

var maxnD = 1

func genRandVecD() ([]data.Matrix, []data.Matrix) {
	x := make([]data.Matrix, len(paramsQ))
	y := make([]data.Matrix, len(paramsQ))

	for i := 0; i < len(paramsQ); i++ {
		var sampler = sample.NewUniformRange(new(big.Int).Add(new(big.Int).Neg(paramsQ[i].bound), big.NewInt(1)), paramsQ[i].bound)
		x[i], _ = data.NewRandomMatrix(maxnQ, paramsQ[i].l, sampler)
		y[i], _ = data.NewRandomMatrix(maxnQ, paramsQ[i].l, sampler)
	}
	return x, y
}

var Xd, Yd = genRandVecD()




func TestBenchDMCFE(t *testing.T) {
	f, err := os.Create("benchmark_results_dmcfe.txt")
	if err != nil {
		t.Fatalf("Error: %v", err)

	}

	label := "bla"
	for j, par := range paramsD {
		//sampler := sample.NewUniformRange(new(big.Int).Add(new(big.Int).Neg(par.bound), big.NewInt(1)), par.bound)

		//y, _ := data.NewRandomMatrix(maxnQ, par.l, sampler)
		//x, _ := data.NewRandomMatrix(maxnQ, par.l, sampler)
		y := Yd[j]
		x := Xd[j]
		//xyCheck, _ := x[0].Dot(y[1])

		clients := make([]*fullysec.DMCFEClient, par.l)
		var err error
		key := make([][]data.VectorG2, maxnD)
		ciphertext := make([][]*bn256.G1, maxnD)
		pubKeys := make([]*bn256.G1, par.l)

		//var xy *big.Int
		var res testing.BenchmarkResult
		res = testing.Benchmark(func(b *testing.B) {
			for k := 0; k < b.N; k++ {
				for i := 0; i < par.l; i++ {
					clients[i], err = fullysec.NewDMCFEClient(i)
					if err != nil {
						t.Fatalf("could not instantiate fullysec.Client: %v", err)
					}
				}
			}
		})
		f.Write([]byte("K " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(int(res.NsPerOp())) + " " + strconv.Itoa(int(res.N)) + "\n"))


		for i := 0; i < par.l; i++ {
			pubKeys[i] = clients[i].ClientPubKey
		}

		res = testing.Benchmark(func(b *testing.B) {
			for k := 0; k < b.N; k++ {
				for i := 0; i < par.l; i++ {
					clients[i].SetShare(pubKeys)
					if err != nil {
						t.Fatalf("Error: %v", err)
					}
				}
			}
		})
		f.Write([]byte("K2 " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(int(res.NsPerOp())) + " " + strconv.Itoa(int(res.N)) + "\n"))


		res = testing.Benchmark(func(b *testing.B) {
			for k := 0; k < b.N; k++ {
				if k < maxnQ {
					key[k] = make([]data.VectorG2, par.l)
					for i := 0; i < par.l; i++ {
						key[k][i], err = clients[i].DeriveKeyShare(y[k])
						if err != nil {
							t.Fatalf("Error: %v", err)
						}
					}

				} else {
					for i := 0; i < par.l; i++ {
						key[k%maxnD][i], err = clients[i].DeriveKeyShare(y[k%maxnD])
						if err != nil {
							t.Fatalf("Error: %v", err)
						}
					}
				}
			}
		})
		f.Write([]byte("F " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(int(res.NsPerOp())) + " " + strconv.Itoa(int(res.N)) + "\n"))


		res = testing.Benchmark(func(b *testing.B) {
			for k := 0; k < b.N; k++ {
				if k < maxnQ {
					ciphertext[k] = make([]*bn256.G1, par.l)
					for i := 0; i < par.l; i++ {
						ciphertext[k][i], err = clients[i].Encrypt(x[k][i], label)
						if err != nil {
							t.Fatalf("Error: %v", err)
						}
					}

				} else {
					for i := 0; i < par.l; i++ {
						ciphertext[k%maxnD][i], err = clients[i].Encrypt(x[k%maxnD][i], label)
						if err != nil {
							t.Fatalf("Error: %v", err)
						}
					}
				}
			}
		})
		f.Write([]byte("E " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(int(res.NsPerOp())) + " " + strconv.Itoa(int(res.N)) + "\n"))

		bound :=  new(big.Int).Mul(par.bound, par.bound)
		bound.Mul(bound, big.NewInt(int64(par.l))) // numClients * (coordinate_bound)^2

		res = testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := fullysec.DMCFEDecrypt(ciphertext[i%maxnD], key[i%maxnD], y[i%maxnD], label, bound)
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

// todo: quad merge
func TestBenchDecDam(t *testing.T) {
	f, err := os.Create("benchmark_results_sgp.txt")
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
		var scheme *quadratic.SGP
		var masterSecKey *quadratic.SGPSecKey
		key := make([]*bn256.G2, maxnQ)
		ciphertext := make([]*quadratic.SGPCipher, maxnQ)

		//var xy *big.Int
		var res testing.BenchmarkResult
		res = testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				scheme = quadratic.NewSGP(par.l, par.bound)
			}
		})
		f.Write([]byte("S " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(int(res.NsPerOp())) + " " + strconv.Itoa(int(res.N)) + "\n"))

		res = testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				masterSecKey, err = scheme.GenerateMasterKey()
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
					key[i], err = scheme.DeriveKey(masterSecKey, ff[i])
				} else {
					_, err = scheme.DeriveKey(masterSecKey, ff[i%maxnQ])
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
					ciphertext[i], err = scheme.Encrypt(x[i], y[i], masterSecKey)
				} else {
					_, err = scheme.Encrypt(x[i%maxnQ], y[i%maxnQ], masterSecKey)
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
				_, err = scheme.Decrypt(ciphertext[i%maxnQ], key[i%maxnQ], ff[i%maxnQ])
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
