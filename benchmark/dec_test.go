package benchmark_test

import (
	"math/big"
	"testing"

	"os"
	"strconv"

	"time"

	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/innerprod/fullysec"
	"github.com/fentec-project/gofe/sample"
)

// paramBounds holds the boundaries for acceptable mean
// and variance values.
type decParams struct {
	l     int
	bound *big.Int
}

var paramsD = []decParams{
	{l: 1, bound: big.NewInt(1000)},
	{l: 5, bound: big.NewInt(1000)},
	{l: 10, bound: big.NewInt(1000)},
	{l: 20, bound: big.NewInt(1000)},
	{l: 50, bound: big.NewInt(1000)},
	//{l: 100, bound: big.NewInt(1000)},
	//{l: 200, bound: big.NewInt(1000)},
	{l: 10, bound: big.NewInt(10)},
	{l: 10, bound: big.NewInt(100)},
	//{l: 10, bound: big.NewInt(10000)},
	//{l: 10, bound: big.NewInt(100000),},
}

var maxnD = 100

func genRandVecD() ([]data.Matrix, []data.Matrix) {
	x := make([]data.Matrix, len(paramsD))
	y := make([]data.Matrix, len(paramsD))

	for i := 0; i < len(paramsD); i++ {
		var sampler = sample.NewUniformRange(new(big.Int).Add(new(big.Int).Neg(paramsD[i].bound), big.NewInt(1)), paramsD[i].bound)
		x[i], _ = data.NewRandomMatrix(maxnQ, paramsD[i].l, sampler)
		y[i], _ = data.NewRandomMatrix(maxnQ, paramsD[i].l, sampler)
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
	for k, par := range paramsD {

		y := Yd[k]
		x := Xd[k]

		clients := make([][]*fullysec.DMCFEClient, maxnD)
		pubKeys := make([][]*bn256.G1, maxnD)
		key := make([][]data.VectorG2, maxnD)
		ciphertext := make([][]*bn256.G1, maxnD)
		for i := 0; i < maxnD; i++ {
			clients[i] = make([]*fullysec.DMCFEClient, par.l)
			pubKeys[i] = make([]*bn256.G1, par.l)
			key[i] = make([]data.VectorG2, par.l)
			ciphertext[i] = make([]*bn256.G1, par.l)
		}

		var err error

		//var xy *big.Int
		var res = make([]int64, maxnD)
		var res2 = make([]int64, maxnD*par.l)
		var start time.Time
		var elapsed time.Duration

		for i := 0; i < maxnD; i++ {
			for j := 0; j < par.l; j++ {

				start = time.Now()
				clients[i][j], err = fullysec.NewDMCFEClient(j)
				elapsed = time.Since(start)
				res2[i*par.l+j] = elapsed.Microseconds()
				if err != nil {
					t.Fatalf("could not instantiate fullysec.Client: %v", err)
				}
			}

		}
		f.Write([]byte("K1 " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(avgSlice(res2)) + "\n"))

		for i := 0; i < maxnD; i++ {
			for j := 0; j < par.l; j++ {
				pubKeys[i][j] = clients[i][j].ClientPubKey
			}
		}

		for i := 0; i < maxnD; i++ {
			for j := 0; j < par.l; j++ {
				start = time.Now()
				clients[i][j].SetShare(pubKeys[i])
				elapsed = time.Since(start)
				res2[i*par.l+j] = elapsed.Microseconds()
				if err != nil {
					t.Fatalf("Error: %v", err)
				}
			}
		}
		f.Write([]byte("K2 " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(avgSlice(res2)) + "\n"))

		for i := 0; i < maxnD; i++ {
			for j := 0; j < par.l; j++ {
				start = time.Now()
				key[i][j], err = clients[i][j].DeriveKeyShare(y[i])
				elapsed = time.Since(start)
				res2[i*par.l+j] = elapsed.Microseconds()
				if err != nil {
					t.Fatalf("Error: %v", err)
				}
			}
		}

		f.Write([]byte("F " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(avgSlice(res2)) + "\n"))

		for i := 0; i < maxnD; i++ {
			for j := 0; j < par.l; j++ {
				start = time.Now()
				ciphertext[i][j], err = clients[i][j].Encrypt(x[i][j], label)
				elapsed = time.Since(start)
				res2[i*par.l+j] = elapsed.Microseconds()
				if err != nil {
					t.Fatalf("Error: %v", err)
				}
			}
		}

		f.Write([]byte("E " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(avgSlice(res2)) + "\n"))

		bound := new(big.Int).Mul(par.bound, par.bound)
		bound.Mul(bound, big.NewInt(int64(par.l))) // numClients * (coordinate_bound)^2

		for i := 0; i < maxnD; i++ {
			start = time.Now()
			_, err := fullysec.DMCFEDecrypt(ciphertext[i], key[i], y[i], label, bound)
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

// todo: quad merge
func TestBenchDecDam(t *testing.T) {
	f, err := os.Create("benchmark_results_dec_dam.txt")
	if err != nil {
		t.Fatalf("Error: %v", err)

	}

	for k, par := range paramsD {
		yVecs := Yd[k]
		y := make([]data.Matrix, maxnD)
		for i := 0; i < maxnD; i++ {
			yMat := make(data.Matrix, 1)
			yMat[0] = yVecs[i]
			y[i] = yMat.Transpose()
		}

		xVecs := Xd[k]
		x := make([][]data.Vector, maxnD)
		for i := 0; i < maxnD; i++ {
			xVec := make([]data.Vector, par.l)
			for k := 0; k < par.l; k++ {
				xVec[k] = make(data.Vector, 1)
				xVec[k][0] = xVecs[i][k]
			}
			x[i] = xVec
		}

		//xyCheck, _ := x[0].Dot(y[1])

		var err error

		damg, err := fullysec.NewDamgardMultiPrecomp(par.l, 1, 2048, par.bound)
		if err != nil {
			t.Fatalf("could not instantiate damgard: %v", err)
		}

		clients := make([][]*fullysec.DamgardDecMultiClient, maxnD)
		pubKeys := make([][]*big.Int, maxnD)
		key := make([][]*fullysec.DamgardDecMultiDerivedKeyPart, maxnD)
		ciphertext := make([][]data.Vector, maxnD)
		secKeys := make([][]*fullysec.DamgardDecMultiSecKey, maxnD)
		for i := 0; i < maxnD; i++ {
			clients[i] = make([]*fullysec.DamgardDecMultiClient, par.l)
			pubKeys[i] = make([]*big.Int, par.l)
			key[i] = make([]*fullysec.DamgardDecMultiDerivedKeyPart, par.l)
			ciphertext[i] = make([]data.Vector, par.l)
			secKeys[i] = make([]*fullysec.DamgardDecMultiSecKey, par.l)
		}


		//var xy *big.Int
		var res = make([]int64, maxnD)
		var res2 = make([]int64, maxnD*par.l)
		var start time.Time
		var elapsed time.Duration

		for i := 0; i < maxnD; i++ {
			for j := 0; j < par.l; j++ {

				start = time.Now()
				clients[i][j], err = fullysec.NewDamgardDecMultiClient(j, damg)
				elapsed = time.Since(start)
				res2[i*par.l+j] = elapsed.Microseconds()
				if err != nil {
					t.Fatalf("could not instantiate fullysec.Client: %v", err)
				}
			}

		}
		f.Write([]byte("K1 " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(avgSlice(res2)) + "\n"))

		for i := 0; i < maxnD; i++ {
			for j := 0; j < par.l; j++ {
				pubKeys[i][j] = clients[i][j].ClientPubKey
			}
		}

		for i := 0; i < maxnD; i++ {
			for j := 0; j < par.l; j++ {
				start = time.Now()
				clients[i][j].SetShare(pubKeys[i])
				secKeys[i][j], err = clients[i][j].GenerateKeys()
				elapsed = time.Since(start)
				res2[i*par.l+j] = elapsed.Microseconds()
				if err != nil {
					t.Fatalf("Error: %v", err)
				}
			}
		}
		f.Write([]byte("K2 " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(avgSlice(res2)) + "\n"))

		for i := 0; i < maxnD; i++ {
			for j := 0; j < par.l; j++ {
				start = time.Now()
				key[i][j], err = clients[i][j].DeriveKeyShare(secKeys[i][j], y[i])
				elapsed = time.Since(start)
				res2[i*par.l+j] = elapsed.Microseconds()
				if err != nil {
					t.Fatalf("Error: %v", err)
				}
			}
		}

		f.Write([]byte("F " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(avgSlice(res2)) + "\n"))

		for i := 0; i < maxnD; i++ {
			for j := 0; j < par.l; j++ {
				start = time.Now()
				ciphertext[i][j], err = clients[i][j].Encrypt(x[i][j], secKeys[i][j])
				elapsed = time.Since(start)
				res2[i*par.l+j] = elapsed.Microseconds()
				if err != nil {
					t.Fatalf("Error: %v", err)
				}
			}
		}

		f.Write([]byte("E " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(avgSlice(res2)) + "\n"))

		bound := new(big.Int).Mul(par.bound, par.bound)
		bound.Mul(bound, big.NewInt(int64(par.l))) // numClients * (coordinate_bound)^2
		decryptor := fullysec.NewDamgardDecMultiDec(damg)

		for i := 0; i < maxnD; i++ {
			start = time.Now()
			_, err := decryptor.Decrypt(ciphertext[i], key[i], y[i])
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
