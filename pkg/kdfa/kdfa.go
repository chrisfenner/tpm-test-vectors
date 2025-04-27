// Package kdfa generates test vectors for the KDFa function from TPM 2.0.
package kdfa

import (
	"fmt"
	"math/rand"
	"strings"

	"github.com/chrisfenner/tpm-test-vectors/pkg/util"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

type TestVector struct {
	Name     string
	HashAlg  uint16
	Key      util.HexBytes
	Label    string
	ContextU util.HexBytes
	ContextV util.HexBytes
	Bits     int
	Result   util.HexBytes
}

func (v *TestVector) VectorName() string {
	return v.Name
}

func (v *TestVector) SetName(name string) {
	v.Name = name
}

// GenerateTestVector generates a KDFa test vector.
// Note that since the TPM doesn't expose a raw KDFa primitive, the TPM
// isn't used here. In the future, we could rig up something that starts an
// auth session in the TPM and checks that we got the session key right.
// For now, we trust the implementation of go-tpm's KDFa.
func GenerateTestVector(_ transport.TPM) (*TestVector, error) {
	var testName strings.Builder

	algID := util.RandomHashAlg()
	hash, err := algID.Hash()
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(&testName, "%s_", util.PrettyAlgName(algID))

	key := util.RandomBytesRandomLength(hash.Size())
	label := util.RandomLabel()
	contextU := util.RandomBytesRandomLength(hash.Size())
	contextV := util.RandomBytesRandomLength(hash.Size())
	bits := rand.Intn(1000)
	fmt.Fprintf(&testName, "%d", bits)

	result := tpm2.KDFa(hash, key, label, contextU, contextV, bits)
	return &TestVector{
		Name:     testName.String(),
		HashAlg:  uint16(algID),
		Key:      key,
		Label:    label,
		ContextU: contextU,
		ContextV: contextV,
		Bits:     bits,
		Result:   result,
	}, nil
}
