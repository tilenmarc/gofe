package quadratic

import (
	"testing"
	"math/big"
	"github.com/fentec-project/gofe/sample"
	"github.com/fentec-project/gofe/data"
	"github.com/cloudflare/bn256"
	"github.com/stretchr/testify/assert"
)

// paramBounds holds the boundaries for acceptable mean
// and variance values.
type sgpParams struct {
	l     int
	bound *big.Int
}

func BenchmarkSgp(b *testing.B) {
	params := []sgpParams{
		//{n: 64, l: 20, bound: big.NewInt(100000),},
		//{n: 128, l: 20, bound: big.NewInt(10000),},
		//{n: 128, l: 160, bound: big.NewInt(10000),},
		//{n: 128, l: 20, bound: big.NewInt(1000000),},
		{l: 10, bound: big.NewInt(100),},
		{l: 10, bound: big.NewInt(1000),},
		{l: 50, bound: big.NewInt(100),},

	}

	var err error
	var sgp *SGP
	var msk *SGPSecKey
	var key *bn256.G2
	var ciphertext *SGPCipher
	var f data.Matrix
	var x, y data.Vector
	var dec *big.Int
	for _, par := range params {
		sampler := sample.NewUniformRange(new(big.Int).Add(new(big.Int).Neg(par.bound), big.NewInt(1)), par.bound)
		f, err = data.NewRandomMatrix(par.l, par.l, sampler)
		if err != nil {
			b.Fatalf("error when generating random matrix: %v", err)
		}
		x, err = data.NewRandomVector(par.l, sampler)
		if err != nil {
			b.Fatalf("error when generating random vector: %v", err)
		}
		y, err = data.NewRandomVector(par.l, sampler)
		if err != nil {
			b.Fatalf("error when generating random vector: %v", err)
		}
		check, err := f.MulXMatY(x, y)
		b.Run("set_up", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				sgp = NewSGP(par.l, par.bound)
				if err != nil {
					b.Fatalf("Error: %v", err)
				}
			}
		})
		b.Run("key_gen", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				msk, err = sgp.GenerateMasterKey()
			}
		})
		b.Run("key_derive", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				key, err = sgp.DeriveKey(msk, f)
				if err != nil {
					b.Fatalf("Error: %v", err)
				}
			}
		})
		b.Run("encrypt", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				ciphertext, err = sgp.Encrypt(x, y, msk)
				if err != nil {
					b.Fatalf("Error: %v", err)
				}
			}
		})
		b.Run("decrypt", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				dec, err = sgp.Decrypt(ciphertext, key, f)
				if err != nil {
					b.Fatalf("Error: %v", err)
				}

			}

		})
		assert.Equal(b, dec.Cmp(check), 0, "obtained incorrect inner product")
	}
}
