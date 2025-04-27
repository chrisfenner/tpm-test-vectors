// Package kdfe generates test vectors for the KDFe function from TPM 2.0.
package kdfe

import (
	"fmt"
	"math/rand"
	"strings"

	"github.com/chrisfenner/tpm-test-vectors/pkg/util"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

type TestVector struct {
	Name       string
	HashAlg    uint16
	Z          util.HexBytes
	Use        string
	PartyUInfo util.HexBytes
	PartyVInfo util.HexBytes
	Bits       int
	Result     util.HexBytes
}

func (v *TestVector) VectorName() string {
	return v.Name
}

func (v *TestVector) SetName(name string) {
	v.Name = name
}

// GenerateTestVector generates a KDFe test vector.
// Note that since the TPM doesn't expose a raw KDFe primitive, the TPM
// isn't used here. In the future, we could rig up something that uses an ECDH
// Restricted Decryption flow in the TPM to check.
func GenerateTestVector(_ transport.TPM) (*TestVector, error) {
	var testName strings.Builder

	algID := util.RandomHashAlg()
	hash, err := algID.Hash()
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(&testName, "%s_", util.PrettyAlgName(algID))

	z := util.RandomBytesRandomLength(hash.Size())
	use := util.RandomLabel()
	partyUInfo := util.RandomBytesRandomLength(hash.Size())
	partyVInfo := util.RandomBytesRandomLength(hash.Size())
	bits := rand.Intn(1000)
	fmt.Fprintf(&testName, "%d", bits)

	result := tpm2.KDFe(hash, z, use, partyUInfo, partyVInfo, bits)
	return &TestVector{
		Name:       testName.String(),
		HashAlg:    uint16(algID),
		Z:          z,
		Use:        use,
		PartyUInfo: partyUInfo,
		PartyVInfo: partyVInfo,
		Bits:       bits,
		Result:     result,
	}, nil
}
