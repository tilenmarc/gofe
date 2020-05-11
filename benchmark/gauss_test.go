package benchmark

import (
	"testing"
	"os"
	"math/big"
	"github.com/fentec-project/gofe/sample"
	"github.com/fentec-project/gofe/data"
	"time"
	"strconv"
)

var num = 1000000

func TestBenchGauss(t *testing.T) {
	f, err := os.Create("benchmark_results_gauss.txt")
	if err != nil {
		t.Fatalf("Error: %v", err)
	}


	var start time.Time
	var elapsed time.Duration
	for i := 0; i< 11; i++ {
		bits := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(i)), nil)
		k := new(big.Int).Exp(big.NewInt(2), bits, nil)
		sampler := sample.NewNormalDoubleConstant(k)
		start = time.Now()
		_, err := data.NewRandomVector(num, sampler)
		elapsed = time.Since(start)
		if err != nil {
			t.Fatalf("Error: %v", err)
		}
		f.Write([]byte("$2^{" + bits.String() + "}$ & " + strconv.FormatFloat(float64(elapsed.Milliseconds())/1000, 'f', 4, 64) + "\\\\ \n"))
	}
	f.Close()

}