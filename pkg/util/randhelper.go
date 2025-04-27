package util

import (
	cryptorand "crypto/rand"
	"math/rand"

	"github.com/google/go-tpm/tpm2"
)

func RandomBool() bool {
	return rand.Intn(2) == 0
}

var hashes = []tpm2.TPMIAlgHash{
	tpm2.TPMAlgSHA1,
	tpm2.TPMAlgSHA256,
	tpm2.TPMAlgSHA384,
	tpm2.TPMAlgSHA512,
}

func RandomHashAlg() tpm2.TPMIAlgHash {
	idx := rand.Intn(len(hashes))
	return hashes[idx]
}

var encapsLabels = []string{
	"DUPLICATE",
	"IDENTITY",
	"SECRET",
}

func RandomEncapsulationLabel() string {
	idx := rand.Intn(len(encapsLabels))
	return encapsLabels[idx]
}

var keyBits = []tpm2.TPMKeyBits{
	128,
	256,
}

func RandomKeyBits() tpm2.TPMKeyBits {
	idx := rand.Intn(len(keyBits))
	return keyBits[idx]
}

func RandomBytes(length int) []byte {
	result := make([]byte, length)
	cryptorand.Read(result[:])
	// Force the first/last byte to some values for edge-case probing.
	switch rand.Intn(5) {
	case 0:
		// Do nothing
	case 1:
		result[0] = 0
	case 2:
		result[0] = 0xff
	case 3:
		result[length-1] = 0
	case 4:
		result[length-1] = 0xff
	}
	return result
}
