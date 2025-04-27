// Package kdfa generates test vectors for the KDFa function from TPM 2.0.
package kdfa

import (
	"math/rand"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

type TestVector struct {
	HashAlg  uint16
	Key      []byte
	Label    string
	ContextU []byte
	ContextV []byte
	Bits     int
	Result   []byte
}

func (v *TestVector) VectorName() string {
	return "TODO"
}

func (v *TestVector) SetName(name string) {
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
	"ATH",
	"CFB",
	"DUPLICATE",
	"IDENTITY",
	"INTEGRITY",
	"OBFUSCATE",
	"SECRET",
	"STORAGE",
}

func randomLabel() string {
	idx := rand.Intn(len(labels))
	return labels[idx]
}

// GenerateTestVector generates a KDFa test vector.
// Note that since the TPM doesn't expose a raw KDFa primitive, the TPM
// isn't used here. In the future, we could rig up something that starts an
// auth session in the TPM and checks that we got the session key right.
// For now, we trust the implementation of go-tpm's KDFa.
func GenerateTestVector(_ transport.TPM) (*TestVector, error) {
	algID := randomHashAlg()
	hash, err := algID.Hash()
	if err != nil {
		return nil, err
	}
	key := randomBytes(0, hash.Size())
	label := randomLabel()
	contextU := randomBytes(0, hash.Size())
	contextV := randomBytes(0, hash.Size())
	bits := rand.Intn(600)
	result := tpm2.KDFa(hash, key, label, contextU, contextV, bits)
	return &TestVector{
		HashAlg:  uint16(algID),
		Key:      key,
		Label:    label,
		ContextU: contextU,
		ContextV: contextV,
		Bits:     bits,
		Result:   result,
	}, nil
}
