package benchmark_test

import (
"testing"

"os"
"strconv"
"time"

"github.com/fentec-project/gofe/innerprod/fullysec"
	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/data"
	"math/big"
	"github.com/fentec-project/gofe/sample"
)



func TestBenchFHIPE(t *testing.T) {
	f, err := os.Create("benchmark_results_fhipe.txt")
	if err != nil {
		t.Fatalf("Error: %v", err)

	}

	for j, par := range params {
		y := Y[j]
		x := X[j]
		var err error
		schemes := make([]*fullysec.FHIPE, maxN)
		masterSecKey := make([]*fullysec.FHIPESecKey, maxN)
		//masterPubKey := make([]data.Vector, maxN)
		key := make([]*fullysec.FHIPEDerivedKey, maxN)
		ciphertext := make([]*fullysec.FHIPECipher, maxN)

		//var xy *big.Int
		var res = make([]int64, maxN)
		var start time.Time
		var elapsed time.Duration

		for i := 0; i < maxN; i++ {
			start = time.Now()
			schemes[i], err = fullysec.NewFHIPE(par.l, par.bound, par.bound)
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
			masterSecKey[i], err = schemes[i].GenerateMasterKey()
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
			key[i], err = schemes[i].DeriveKey(y[i], masterSecKey[i])
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
			ciphertext[i], err = schemes[i].Encrypt(x[i], masterSecKey[i])
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
			_, err = schemes[i].Decrypt(ciphertext[i], key[i])
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

func TestBenchFHMultiIPE(t *testing.T) {
	f, err := os.Create("benchmark_results_fh_multi_ipe.txt")
	if err != nil {
		t.Fatalf("Error: %v", err)

	}

	for j, par := range params {
		y := Y[j]
		x := X[j]
		var err error
		schemes := make([]*fullysec.FHMultiIPE, maxN)
		masterSecKey := make([]*fullysec.FHMultiIPESecKey, maxN)
		masterPubKey := make([]*bn256.GT, maxN)
		key := make([]data.MatrixG2, maxN)
		ciphertext := make([]data.MatrixG1, maxN)

		//var xy *big.Int
		var res = make([]int64, maxN)
		var start time.Time
		var elapsed time.Duration

		for i := 0; i < maxN; i++ {
			start = time.Now()
			schemes[i] = fullysec.NewFHMultiIPE(2, par.l, 1, par.bound, par.bound)
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
			masterSecKey[i], masterPubKey[i], err = schemes[i].GenerateKeys()
			elapsed = time.Since(start)
			res[i] = elapsed.Microseconds()
			if err != nil {
				t.Fatalf("Error: %v", err)
			}
		}
		f.Write([]byte("K " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(avgSlice(res)) + "\n"))

		for i := 0; i < maxN; i++ {
			yMat := data.NewConstantMatrix(par.l, 1, big.NewInt(0))
			for ii:=0; ii<len(y[i]); ii++ {
				yMat[ii][0].Set(y[i][ii])
			}

			start = time.Now()
			key[i], err = schemes[i].DeriveKey(yMat, masterSecKey[i])
			elapsed = time.Since(start)
			res[i] = elapsed.Microseconds()

			if err != nil {
				t.Fatalf("Error: %v", err)
			}
		}

		f.Write([]byte("F " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(avgSlice(res)) + "\n"))

		for i := 0; i < maxN; i++ {
			xMat := data.NewConstantMatrix(par.l, 1, big.NewInt(0))
			for ii:=0; ii<len(y[i]); ii++ {
				xMat[ii][0].Set(x[i][ii])
			}
			ciphertext[i] = make(data.MatrixG1, par.l)
			start = time.Now()
			for ii:=0; ii<len(y[i]); ii++ {
				ciphertext[i][ii], err = schemes[i].Encrypt(xMat[ii], masterSecKey[i].BHat[ii])
			}
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
			_, err = schemes[i].Decrypt(ciphertext[i], key[i], masterPubKey[i])
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


func TestBenchFHPartIPE(t *testing.T) {
	f, err := os.Create("benchmark_results_fh_part_ipe.txt")
	if err != nil {
		t.Fatalf("Error: %v", err)

	}

	for j, par := range params {
		y := Y[j]
		x := X[j]
		var err error
		schemes := make([]*fullysec.PartFHIPE, maxN)
		masterSecKey := make([]*fullysec.PartFHIPESecKey, maxN)
		masterPubKey := make([]*fullysec.PartFHIPEPubKey, maxN)
		key := make([]data.VectorG2, maxN)
		ciphertext := make([]data.VectorG1, maxN)

		//var xy *big.Int
		var res = make([]int64, maxN)
		var start time.Time
		var elapsed time.Duration

		for i := 0; i < maxN; i++ {
			start = time.Now()
			schemes[i], err = fullysec.NewPartFHIPE(par.l, par.bound)
			elapsed = time.Since(start)
			res[i] = elapsed.Microseconds()
			if err != nil {
				t.Fatalf("Error: %v", err)
			}

		}
		f.Write([]byte("S " + strconv.Itoa(par.l) + " " + par.bound.String() + " " +
			strconv.Itoa(avgSlice(res)) + "\n"))

		// choose a subspace in which encryption will be allowed
		k := 1 // dimension of the subspace
		// the subspace is given by the columns of the matrix m
		// we sample m with not too big inputs
		samplerM := sample.NewUniform(new(big.Int).Div(par.bound, big.NewInt(int64(k))))
		m, err := data.NewRandomMatrix(par.l, k, samplerM)
		for i := 0; i < maxN; i++ {
			start = time.Now()
			masterPubKey[i], masterSecKey[i], err = schemes[i].GenerateKeys(m)
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
			key[i], err = schemes[i].DeriveKey(y[i], masterSecKey[i])
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
			ciphertext[i], err = schemes[i].SecEncrypt(x[i], masterPubKey[i], masterSecKey[i])
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
			_, err = schemes[i].Decrypt(ciphertext[i], key[i])
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
