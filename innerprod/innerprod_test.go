package innerprod

import (
	"testing"
	"math/big"
	"github.com/fentec-project/gofe/sample"
	"github.com/fentec-project/gofe/innerprod/fullysec"
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

func TestInnerProductSchemes(t *testing.T) {

	params := []innerprodParams{
		{
			n:      32,
			l:      10,
			bound: big.NewInt(10),
		},
		{
			n:      64,
			l:      10,
			bound: big.NewInt(10000),
		},
		{
			n:      64,
			l:      10,
			bound: big.NewInt(1000000),
		},
		//{
		//	n:      128,
		//	l:      10,
		//	bound: big.NewInt(10000),
		//},
		//{
		//	n:      128,
		//	l:      10,
		//	bound: big.NewInt(1000000),
		//},
	}


	for _, par := range params {
		sampler := sample.NewUniformRange(new(big.Int).Neg(par.bound), par.bound)
		y, _ := data.NewRandomVector(par.l, sampler)
		x, _ := data.NewRandomVector(par.l, sampler)
		xyCheck, _ := x.Dot(y)
		t.Run("fully_damgard", func(t *testing.T) {
			testFullyDamgard(t, par, x, y, xyCheck)
		})
		t.Run("fully_lwe", func(t *testing.T) {
			testFullyLwe(t, par, x, y, xyCheck)
		})
		t.Run("simple_damgard", func(t *testing.T) {
			testSimpleDamgard(t, par, x, y, xyCheck)
		})
		t.Run("simple_lwe", func(t *testing.T) {
			testSimpleLwe(t, par, x, y, xyCheck)
		})
	}
}

func testFullyDamgard(t *testing.T, par innerprodParams, x, y data.Vector, xyCheck *big.Int) {
	damgard, _ := fullysec.NewDamgard(par.l, par.n, par.bound)
	masterSecKey, masterPubKey, _ := damgard.GenerateMasterKeys()
	key, _ := damgard.DeriveKey(masterSecKey, y)
	encryptor := fullysec.NewDamgardFromParams(damgard.Params)
	ciphertext, _ := encryptor.Encrypt(x, masterPubKey)
	decryptor := fullysec.NewDamgardFromParams(damgard.Params)
	xy, _ := decryptor.Decrypt(ciphertext, key, y)
	assert.Equal(t, xy.Cmp(xyCheck), 0, "obtained incorrect inner product")
}

func testFullyLwe(t *testing.T, par innerprodParams, x, y data.Vector, xyCheck *big.Int) {
	fsLWE, _ := fullysec.NewLWE(par.l, par.n, par.bound, par.bound)
	Z, _ := fsLWE.GenerateSecretKey()
	U, _ := fsLWE.GeneratePublicKey(Z)
	zY, _ := fsLWE.DeriveKey(y, Z)
	cipher, _ := fsLWE.Encrypt(x, U)
	xyDecrypted, _ := fsLWE.Decrypt(cipher, zY, y)
	assert.Equal(t, xyCheck.Cmp(xyDecrypted), 0, "obtained incorrect inner product")
}

func testSimpleDamgard(t *testing.T, par innerprodParams, x, y data.Vector, xyCheck *big.Int) {
	simpleDDH, _ := simple.NewDDH(par.l, par.n, par.bound)
	masterSecKey, masterPubKey, _ := simpleDDH.GenerateMasterKeys()
	funcKey, _ := simpleDDH.DeriveKey(masterSecKey, y)
	encryptor := simple.NewDDHFromParams(simpleDDH.Params)
	ciphertext, _ := encryptor.Encrypt(x, masterPubKey)
	decryptor := simple.NewDDHFromParams(simpleDDH.Params)
	xy, _ := decryptor.Decrypt(ciphertext, funcKey, y)
	assert.Equal(t, xy, xyCheck, "Original and decrypted values should match")
}

func testSimpleLwe(t *testing.T, par innerprodParams, x, y data.Vector, xyCheck *big.Int) {
	simpleLWE, _ := simple.NewLWE(par.l, par.bound, par.bound, par.n)
	SK, _ := simpleLWE.GenerateSecretKey()
	PK, _ := simpleLWE.GeneratePublicKey(SK)
	skY, _ := simpleLWE.DeriveKey(y, SK)
	cipher, _ := simpleLWE.Encrypt(x, PK)
	xyDecrypted, _ := simpleLWE.Decrypt(cipher, skY, y)
	assert.Equal(t, xyCheck.Cmp(xyDecrypted), 0, "obtained incorrect inner product")
}