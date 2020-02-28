package benchmark_test

import (
	"testing"
	"github.com/fentec-project/gofe/internal"
	"github.com/fentec-project/gofe/innerprod/fullysec"
	"math/big"
)



func BenchmarkEC(b *testing.B) {
	g := new(internal.Ec).Gen()
	h, _ := new(internal.Ec).Random()

	b.Run("ECadd", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			g.Add(g, h)
			}
		})
}

func BenchmarkZp(b *testing.B) {
	dam, _ := fullysec.NewDamgardPrecomp(1, 2048, big.NewInt(1))
	g := dam.Params.G
	h := dam.Params.H

	b.Run("Zpadd", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			g.Mul(g, h)
			g.Mod(g, dam.Params.P)
		}
	})
}
