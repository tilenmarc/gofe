package innerprod

import (
	"testing"
	"math/big"

	"github.com/fentec-project/gofe/innerprod/fullysec"
	"github.com/fentec-project/gofe/sample"
	"github.com/fentec-project/gofe/data"
	"github.com/stretchr/testify/assert"
	"github.com/fentec-project/gofe/innerprod/simple"
)

// paramBounds holds the boundaries for acceptable mean
// and variance values.
type innerprodParams struct {
	n, l int
	bound *big.Int
}
// TODO: writing this I noticed: -in generating fullysec or simple LWE struct parameters are in different order
// -in simple we have ddh, in fullysec we have damgard

func BenchmarkFullyDamgard(b *testing.B) {
	params := []innerprodParams{
		//{n: 64, l: 20, bound: big.NewInt(100000),},
		//{n: 128, l: 20, bound: big.NewInt(10000),},
		//{n: 128, l: 160, bound: big.NewInt(10000),},
		//{n: 128, l: 20, bound: big.NewInt(1000000),},
		{n: 256, l: 20, bound: big.NewInt(10000),},
	}

	for _, par := range params {
		sampler := sample.NewUniformRange(new(big.Int).Add(new(big.Int).Neg(par.bound), big.NewInt(1)), par.bound)
		y, _ := data.NewRandomVector(par.l, sampler)
		x, _ := data.NewRandomVector(par.l, sampler)
		xyCheck, _ := x.Dot(y)
		var err error
		var damgard *fullysec.Damgard
		var masterSecKey *fullysec.DamgardSecKey
		var masterPubKey data.Vector
		var key *fullysec.DamgardDerivedKey
		var ciphertext data.Vector
		var xy *big.Int
		b.Run("set_up", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				damgard, err = fullysec.NewDamgard(par.l, par.n, par.bound)
				if err != nil {
					b.Fatalf("Error: %v", err)
				}
			}
		})
		b.Run("key_gen", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				masterSecKey, masterPubKey, _ = damgard.GenerateMasterKeys()
			}
		})
		b.Run("key_derive", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				key, err = damgard.DeriveKey(masterSecKey, y)
				if err != nil {
					b.Fatalf("Error: %v", err)
				}
			}
		})
		b.Run("encrypt", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				ciphertext, err = damgard.Encrypt(x, masterPubKey)
				if err != nil {
					b.Fatalf("Error: %v", err)
				}
			}
		})
		b.Run("decrypt", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				xy, err = damgard.Decrypt(ciphertext, key, y)
				if err != nil {
					b.Fatalf("Error: %v", err)
				}
			}

		})
		assert.Equal(b, xy.Cmp(xyCheck), 0, "obtained incorrect inner product")
	}
}

func BenchmarkFullyLWE(b *testing.B) {
	params := []innerprodParams{
		//{n: 64, l: 20, bound: big.NewInt(100000),},
		//{n: 128, l: 20, bound: big.NewInt(10000),},
		//{n: 128, l: 160, bound: big.NewInt(10000),},
		//{n: 128, l: 20, bound: big.NewInt(1000000),},
		//{n: 256, l: 20, bound: big.NewInt(10000),},
	}

	for _, par := range params {
		sampler := sample.NewUniformRange(new(big.Int).Add(new(big.Int).Neg(par.bound), big.NewInt(1)), par.bound)
		y, _ := data.NewRandomVector(par.l, sampler)
		x, _ := data.NewRandomVector(par.l, sampler)
		xyCheck, _ := x.Dot(y)
		var err error
		var lwe *fullysec.LWE
		var masterSecKey data.Matrix
		var masterPubKey data.Matrix
		var key data.Vector
		var ciphertext data.Vector
		var xy *big.Int
		b.Run("set_up", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				lwe, err = fullysec.NewLWE(par.l, par.n, par.bound, par.bound)
				if err != nil {
					b.Fatalf("Error: %v", err)
				}
			}
		})
		b.Run("key_gen", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				masterSecKey, _ = lwe.GenerateSecretKey()
				if err != nil {
					b.Fatalf("Error: %v", err)
				}
				masterPubKey, _ = lwe.GeneratePublicKey(masterSecKey)
				if err != nil {
					b.Fatalf("Error: %v", err)
				}
			}
		})
		b.Run("key_derive", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				key, err = lwe.DeriveKey(y, masterSecKey)
				if err != nil {
					b.Fatalf("Error: %v", err)
				}
			}
		})
		b.Run("encrypt", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				ciphertext, err = lwe.Encrypt(x, masterPubKey)
				if err != nil {
					b.Fatalf("Error: %v", err)
				}
			}
		})
		b.Run("decrypt", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				xy, err = lwe.Decrypt(ciphertext, key, y)
				if err != nil {
					b.Fatalf("Error: %v", err)
				}
			}

		})
		assert.Equal(b, xy.Cmp(xyCheck), 0, "obtained incorrect inner product")
	}
}


func BenchmarkFullyPaillier(b *testing.B) {
	params := []innerprodParams{
		//{n: 64, l: 20, bound: big.NewInt(100000),},
		//{n: 128, l: 20, bound: big.NewInt(10000),},
		//{n: 128, l: 160, bound: big.NewInt(10000),},
		//{n: 128, l: 20, bound: big.NewInt(1000000),},
		{n: 256, l: 20, bound: big.NewInt(10000),},
	}

	for _, par := range params {
		sampler := sample.NewUniformRange(new(big.Int).Add(new(big.Int).Neg(par.bound), big.NewInt(1)), par.bound)
		y, _ := data.NewRandomVector(par.l, sampler)
		x, _ := data.NewRandomVector(par.l, sampler)
		xyCheck, _ := x.Dot(y)
		var err error
		var paillier *fullysec.Paillier
		var masterSecKey data.Vector
		var masterPubKey data.Vector
		var key *big.Int
		var ciphertext data.Vector
		var xy *big.Int
		b.Run("set_up", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				paillier, err = fullysec.NewPaillier(par.l, par.n, par.n * 4, par.bound, par.bound)
				if err != nil {
					b.Fatalf("Error: %v", err)
				}
			}
		})
		b.Run("key_gen", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				masterSecKey, masterPubKey, _ = paillier.GenerateMasterKeys()
			}
		})
		b.Run("key_derive", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				key, err = paillier.DeriveKey(masterSecKey, y)
				if err != nil {
					b.Fatalf("Error: %v", err)
				}
			}
		})
		b.Run("encrypt", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				ciphertext, err = paillier.Encrypt(x, masterPubKey)
				if err != nil {
					b.Fatalf("Error: %v", err)
				}
			}
		})
		b.Run("decrypt", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				xy, err = paillier.Decrypt(ciphertext, key, y)
				if err != nil {
					b.Fatalf("Error: %v", err)
				}
			}

		})
		assert.Equal(b, xy.Cmp(xyCheck), 0, "obtained incorrect inner product")
	}
}

func BenchmarkSimpleDamgard(b *testing.B) {
	params := []innerprodParams{
		//{n: 64, l: 20, bound: big.NewInt(100000),},
		//{n: 128, l: 20, bound: big.NewInt(10000),},
		//{n: 128, l: 160, bound: big.NewInt(10000),},
		//{n: 128, l: 20, bound: big.NewInt(1000000),},
		{n: 256, l: 20, bound: big.NewInt(10000),},
	}

	for _, par := range params {
		sampler := sample.NewUniformRange(new(big.Int).Add(new(big.Int).Neg(par.bound), big.NewInt(1)), par.bound)
		y, _ := data.NewRandomVector(par.l, sampler)
		x, _ := data.NewRandomVector(par.l, sampler)
		xyCheck, _ := x.Dot(y)
		var err error
		var damgard *simple.DDH
		var masterSecKey data.Vector
		var masterPubKey data.Vector
		var key *big.Int
		var ciphertext data.Vector
		var xy *big.Int
		b.Run("set_up", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				damgard, err = simple.NewDDH(par.l, par.n, par.bound)
				if err != nil {
					b.Fatalf("Error: %v", err)
				}
			}
		})
		b.Run("key_gen", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				masterSecKey, masterPubKey, _ = damgard.GenerateMasterKeys()
			}
		})
		b.Run("key_derive", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				key, err = damgard.DeriveKey(masterSecKey, y)
				if err != nil {
					b.Fatalf("Error: %v", err)
				}
			}
		})
		b.Run("encrypt", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				ciphertext, err = damgard.Encrypt(x, masterPubKey)
				if err != nil {
					b.Fatalf("Error: %v", err)
				}
			}
		})
		b.Run("decrypt", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				xy, err = damgard.Decrypt(ciphertext, key, y)
				if err != nil {
					b.Fatalf("Error: %v", err)
				}
			}
		})
		assert.Equal(b, xy.Cmp(xyCheck), 0, "obtained incorrect inner product")
	}
}


func BenchmarkSimpleLWE(b *testing.B) {
	params := []innerprodParams{
		//{n: 64, l: 20, bound: big.NewInt(100000),},
		//{n: 128, l: 20, bound: big.NewInt(10000),},
		//{n: 128, l: 160, bound: big.NewInt(10000),},
		//{n: 128, l: 20, bound: big.NewInt(1000000),},
		//{n: 256, l: 20, bound: big.NewInt(10000),},
	}

	for _, par := range params {
		sampler := sample.NewUniformRange(new(big.Int).Add(new(big.Int).Neg(par.bound), big.NewInt(1)), par.bound)
		y, _ := data.NewRandomVector(par.l, sampler)
		x, _ := data.NewRandomVector(par.l, sampler)
		xyCheck, _ := x.Dot(y)
		var err error
		var lwe *simple.LWE
		var masterSecKey data.Matrix
		var masterPubKey data.Matrix
		var key data.Vector
		var ciphertext data.Vector
		var xy *big.Int
		b.Run("set_up", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				lwe, err = simple.NewLWE(par.l, par.bound, par.bound, par.n)
				if err != nil {
					b.Fatalf("Error: %v", err)
				}
			}
		})
		b.Run("key_gen", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				masterSecKey, _ = lwe.GenerateSecretKey()
				if err != nil {
					b.Fatalf("Error: %v", err)
				}
				masterPubKey, _ = lwe.GeneratePublicKey(masterSecKey)
				if err != nil {
					b.Fatalf("Error: %v", err)
				}
			}
		})
		b.Run("key_derive", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				key, err = lwe.DeriveKey(y, masterSecKey)
				if err != nil {
					b.Fatalf("Error: %v", err)
				}
			}
		})
		b.Run("encrypt", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				ciphertext, err = lwe.Encrypt(x, masterPubKey)
				if err != nil {
					b.Fatalf("Error: %v", err)
				}
			}
		})
		b.Run("decrypt", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				xy, err = lwe.Decrypt(ciphertext, key, y)
				if err != nil {
					b.Fatalf("Error: %v", err)
				}
			}

		})
		assert.Equal(b, xy.Cmp(xyCheck), 0, "obtained incorrect inner product")
	}
}



//func testFullyDamgard(t *testing.T, par innerprodParams, x, y data.Vector, xyCheck *big.Int) {
//	damgard, _ := fullysec.NewDamgard(par.l, par.n, par.bound)
//	masterSecKey, masterPubKey, _ := damgard.GenerateMasterKeys()
//	key, _ := damgard.DeriveKey(masterSecKey, y)
//	encryptor := fullysec.NewDamgardFromParams(damgard.Params)
//	ciphertext, _ := encryptor.Encrypt(x, masterPubKey)
//	decryptor := fullysec.NewDamgardFromParams(damgard.Params)
//	xy, _ := decryptor.Decrypt(ciphertext, key, y)
//	assert.Equal(t, xy.Cmp(xyCheck), 0, "obtained incorrect inner product")
//}
//
//func benchFullyDamgard(t *testing.B, par innerprodParams, x, y data.Vector, xyCheck *big.Int) {
//	damgard, _ := fullysec.NewDamgard(par.l, par.n, par.bound)
//	masterSecKey, masterPubKey, _ := damgard.GenerateMasterKeys()
//	key, _ := damgard.DeriveKey(masterSecKey, y)
//	encryptor := fullysec.NewDamgardFromParams(damgard.Params)
//	ciphertext, _ := encryptor.Encrypt(x, masterPubKey)
//	decryptor := fullysec.NewDamgardFromParams(damgard.Params)
//	xy, _ := decryptor.Decrypt(ciphertext, key, y)
//	assert.Equal(t, xy.Cmp(xyCheck), 0, "obtained incorrect inner product")
//}
//
//func testFullyLwe(t *testing.T, par innerprodParams, x, y data.Vector, xyCheck *big.Int) {
//	fsLWE, _ := fullysec.NewLWE(par.l, par.n, par.bound, par.bound)
//	Z, _ := fsLWE.GenerateSecretKey()
//	U, _ := fsLWE.GeneratePublicKey(Z)
//	zY, _ := fsLWE.DeriveKey(y, Z)
//	cipher, _ := fsLWE.Encrypt(x, U)
//	xyDecrypted, _ := fsLWE.Decrypt(cipher, zY, y)
//	assert.Equal(t, xyCheck.Cmp(xyDecrypted), 0, "obtained incorrect inner product")
//}
//
//func testSimpleDamgard(t *testing.B, par innerprodParams, x, y data.Vector, xyCheck *big.Int) {
//	simpleDDH, _ := simple.NewDDH(par.l, par.n, par.bound)
//	masterSecKey, masterPubKey, _ := simpleDDH.GenerateMasterKeys()
//	funcKey, _ := simpleDDH.DeriveKey(masterSecKey, y)
//	encryptor := simple.NewDDHFromParams(simpleDDH.Params)
//	ciphertext, _ := encryptor.Encrypt(x, masterPubKey)
//	decryptor := simple.NewDDHFromParams(simpleDDH.Params)
//	xy, _ := decryptor.Decrypt(ciphertext, funcKey, y)
//	assert.Equal(t, xy, xyCheck, "Original and decrypted values should match")
//}
//
//func testSimpleLwe(t *testing.T, par innerprodParams, x, y data.Vector, xyCheck *big.Int) {
//	simpleLWE, _ := simple.NewLWE(par.l, par.bound, par.bound, par.n)
//	SK, _ := simpleLWE.GenerateSecretKey()
//	PK, _ := simpleLWE.GeneratePublicKey(SK)
//	skY, _ := simpleLWE.DeriveKey(y, SK)
//	cipher, _ := simpleLWE.Encrypt(x, PK)
//	xyDecrypted, _ := simpleLWE.Decrypt(cipher, skY, y)
//	assert.Equal(t, xyCheck.Cmp(xyDecrypted), 0, "obtained incorrect inner product")
//}
//
//func testPaillier(t *testing.T, par innerprodParams, x, y data.Vector, xyCheck *big.Int) {
//	paillier, _ := fullysec.NewPaillier(par.l, par.n, par.n * 4, par.bound, par.bound)
//	masterSecKey, masterPubKey, _ := paillier.GenerateMasterKeys()
//	key, _ := paillier.DeriveKey(masterSecKey, y)
//	encryptor := fullysec.NewPaillierFromParams(paillier.Params)
//	ciphertext, _ := encryptor.Encrypt(x, masterPubKey)
//	xy, _ := paillier.Decrypt(ciphertext, key, y)
//	assert.Equal(t, xy.Cmp(xyCheck), 0, "Original and decrypted values should match")
//}


//func TestInnerProductSchemes(t *testing.T) {
//
//	params := []innerprodParams{
//		{
//			n:      64,
//			l:      10,
//			bound: big.NewInt(100000),
//		},
//		//{
//		//	n:      64,
//		//	l:      5,
//		//	bound: big.NewInt(1000),
//		//},
//		//{
//		//	n:      64,
//		//	l:      5,
//		//	bound: big.NewInt(10000),
//		//},
//		//{
//		//	n:      64,
//		//	l:      5,
//		//	bound: big.NewInt(100000),
//		//},
//		////{
//		////	n:      64,
//		////	l:      5,
//		////	bound: big.NewInt(1000000),
//		////},
//		//{
//		//	n:      64,
//		//	l:      20,
//		//	bound: big.NewInt(1000),
//		//},
//		//{
//		//	n:      64,
//		//	l:      20,
//		//	bound: big.NewInt(10000),
//		//},
//		//{
//		//	n:      64,
//		//	l:      20,
//		//	bound: big.NewInt(100000),
//		//},
//		////{
//		////	n:      64,
//		////	l:      20,
//		////	bound: big.NewInt(1000000),
//		////},
//		////{
//		////	n:      128,
//		////	l:      10,
//		////	bound: big.NewInt(1000000),
//		////},
//		////{
//		////	n:      128,
//		////	l:      10,
//		////	bound: big.NewInt(1000000),
//		////},
//	}
//
//
//	for _, par := range params {
//		sampler := sample.NewUniformRange(new(big.Int).Add(new(big.Int).Neg(par.bound), big.NewInt(1)), par.bound)
//		y, _ := data.NewRandomVector(par.l, sampler)
//		x, _ := data.NewRandomVector(par.l, sampler)
//		xyCheck, _ := x.Dot(y)
//		t.Run("fully_damgard", func(t *testing.T) {
//			testFullyDamgard(t, par, x, y, xyCheck)
//		})
//		//t.Run("fully_lwe", func(t *testing.T) {
//		//	testFullyLwe(t, par, x, y, xyCheck)
//		//})
//		//t.Run("simple_damgard", func(t *testing.T) {
//		//	testSimpleDamgard(t, par, x, y, xyCheck)
//		//})
//		//t.Run("simple_lwe", func(t *testing.T) {
//		//	testSimpleLwe(t, par, x, y, xyCheck)
//		//})
//		//t.Run("paillier", func(t *testing.T) {
//		//	testPaillier(t, par, x, y, xyCheck)
//		//})
//	}
//}