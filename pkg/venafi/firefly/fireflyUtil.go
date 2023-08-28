package firefly

import (
	"fmt"

	"github.com/Venafi/vcert/v5/pkg/certificate"
)

func GetRSASize(rsaSize int) (int, error) {
	rsaSizeResult := rsaSize
	if rsaSizeResult == 0 {
		rsaSizeResult = certificate.DefaultRSAlength
	}

	if !rsaSizes[rsaSizeResult] {
		var sizes []int
		for size, _ := range rsaSizes {
			sizes = append(sizes, size)
		}
		return 0, fmt.Errorf("key Size %d is not supported. The valid RSA sizes for Firefly are %v", rsaSize, sizes)
	}

	return rsaSizeResult, nil
}
