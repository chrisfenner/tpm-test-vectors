// Package kdfe generates test vectors for the KDFe function from TPM 2.0.
package kdfe

import (
	"math/rand"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

type TestVector struct {
	HashAlg    uint16
	Z          []byte
	Use        string
	PartyUInfo []byte
	PartyVInfo []byte
	Bits       int
	Result     []byte
}

var hashes = []tpm2.TPMIAlgHash{
	tpm2.TPMAlgSHA1,
	tpm2.TPMAlgSHA256,
	tpm2.TPMAlgSHA384,
	tpm2.TPMAlgSHA512,
}

func randomHashAlg() tpm2.TPMIAlgHash {
	idx := rand.Intn(len(hashes))
	return hashes[idx]
}

func randomBytes(minLen, maxLen int) []byte {
	len := rand.Intn(maxLen - minLen)
	result := make([]byte, len)
	rand.Read(result[:])
	return result
}

var labels = []string{
	"DUPLICATE",
	"IDENTITY",
	"SECRET",
}

func randomLabel() string {
	idx := rand.Intn(len(labels))
	return labels[idx]
}

// GenerateTestVector generates a KDFe test vector.
// Note that since the TPM doesn't expose a raw KDFe primitive, the TPM
// isn't used here. In the future, we could rig up something that uses an ECDH
// Restricted Decryption flow in the TPM to check.
func GenerateTestVector(_ transport.TPM) (*TestVector, error) {
	algID := randomHashAlg()
	hash, err := algID.Hash()
	if err != nil {
		return nil, err
	}
	z := randomBytes(0, hash.Size())
	use := randomLabel()
	partyUInfo := randomBytes(0, hash.Size())
	partyVInfo := randomBytes(0, hash.Size())
	bits := rand.Intn(600)
	result := tpm2.KDFe(hash, z, use, partyUInfo, partyVInfo, bits)
	return &TestVector{
		HashAlg:    uint16(algID),
		Z:          z,
		Use:        use,
		PartyUInfo: partyUInfo,
		PartyVInfo: partyVInfo,
		Bits:       bits,
		Result:     result,
	}, nil
}
