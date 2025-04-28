// Package ecckem generates test vectors for the labeled encapsulation ("Secret Sharing") function from TPM 2.0.
package ecckem

import (
	"crypto/ecdh"
	cryptorand "crypto/rand"
	"fmt"
	"strings"

	"github.com/chrisfenner/tpm-test-vectors/pkg/util"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

type TestVector struct {
	Name             string
	Validated        *string `json:",omitempty"`
	Label            string
	EphemeralPrivate util.HexBytes
	Secret           util.HexBytes
	PublicKey        util.HexBytes
	Ciphertext       util.HexBytes
}

func (v *TestVector) VectorName() string {
	return v.Name
}

func (v *TestVector) SetName(name string) {
	v.Name = name
}

// GenerateTestVector generates an RSA Labeled Encapsulation test vector.
func GenerateTestVector(tpm transport.TPM) (*TestVector, error) {
	var testName strings.Builder

	curve := util.RandomCurve()
	fmt.Fprintf(&testName, "%s_", util.PrettyCurveName(curve))

	nameAlg := util.RandomHashAlg()
	fmt.Fprintf(&testName, "%s_", util.PrettyAlgName(nameAlg))
	hashAlg := nameAlg

	// Randomly decide whether to generate this key as Restricted.
	restricted := util.RandomBool()

	// Symmetric and Scheme depend on whether we chose Restricted.
	// Only a Restricted Decryption key can have Symmetric set.
	// Only a non-Restricted Decryption key can have Scheme set.
	keyBits := util.RandomKeyBits()
	symmetric := tpm2.TPMTSymDefObject{
		Algorithm: tpm2.TPMAlgAES,
		KeyBits: tpm2.NewTPMUSymKeyBits(
			tpm2.TPMAlgAES,
			keyBits,
		),
		Mode: tpm2.NewTPMUSymMode(
			tpm2.TPMAlgAES,
			tpm2.TPMAlgCFB,
		),
	}
	scheme := tpm2.TPMTECCScheme{
		Scheme: tpm2.TPMAlgNull,
	}
	schemeAlg := tpm2.TPMAlgNull
	if !restricted {
		hashAlg = util.RandomHashAlg()
		fmt.Fprintf(&testName, "%s_", util.PrettyAlgName(hashAlg))

		symmetric = tpm2.TPMTSymDefObject{
			Algorithm: tpm2.TPMAlgNull,
		}
		scheme = tpm2.TPMTECCScheme{
			Scheme: tpm2.TPMAlgECDH,
			Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDH, &tpm2.TPMSKeySchemeECDH{
				HashAlg: hashAlg,
			}),
		}
		schemeAlg = hashAlg
	} else {
		fmt.Fprintf(&testName, "%d_", keyBits)
	}

	nameAlgHash, err := nameAlg.Hash()
	if err != nil {
		return nil, err
	}

	// Generate the key in the TPM simulator.
	cp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgECC,
			NameAlg: nameAlg,
			ObjectAttributes: tpm2.TPMAObject{
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
				AdminWithPolicy:     false,
				NoDA:                true,
				Decrypt:             true,
				Restricted:          restricted,
			},
			Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
				CurveID:   curve,
				Symmetric: symmetric,
				Scheme:    scheme,
			}),
		}),
	}.Execute(tpm)
	if err != nil {
		return nil, err
	}
	defer tpm2.FlushContext{FlushHandle: cp.ObjectHandle}.Execute(tpm)

	// Parse the key created by the TPM simulator.
	pub, err := cp.OutPublic.Contents()
	if err != nil {
		return nil, err
	}
	eccParms, err := pub.Parameters.ECCDetail()
	if err != nil {
		return nil, err
	}
	eccUnique, err := pub.Unique.ECC()
	if err != nil {
		return nil, err
	}
	eccPub, err := tpm2.ECDHPub(eccParms, eccUnique)
	if err != nil {
		return nil, err
	}

	// Generate a random key on the same curve.
	ephemeralPriv, err := eccPub.Curve().GenerateKey(cryptorand.Reader)
	if err != nil {
		return nil, err
	}
	ephX, ephY := getXY(ephemeralPriv.PublicKey())
	ciphertext := tpm2.Marshal(tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{
			Buffer: ephX,
		},
		Y: tpm2.TPM2BECCParameter{
			Buffer: ephY,
		},
	})

	pubX, _ := getXY(eccPub)

	z, err := ephemeralPriv.ECDH(eccPub)
	if err != nil {
		return nil, err
	}

	// NOTE: The nameAlg is always used in KDFe, even if the key has an ECDH scheme with a different hash algorithm!
	label := util.RandomEncapsulationLabel()
	secret := tpm2.KDFe(nameAlgHash, z, label, ephX, pubX, nameAlgHash.Size()*8)

	if restricted {
		testName.WriteString("restricted")
	} else {
		testName.WriteString("unrestricted")
	}

	result := TestVector{
		Name:             testName.String(),
		Label:            label,
		EphemeralPrivate: ephemeralPriv.Bytes(),
		Secret:           secret,
		PublicKey:        cp.OutPublic.Bytes(),
		Ciphertext:       ciphertext,
	}

	result.Validated, err = util.ValidateLabeledKEMTestVector(tpm, tpm2.NamedHandle{
		Handle: cp.ObjectHandle,
		Name:   cp.Name,
	}, pub.NameAlg, schemeAlg, &symmetric, restricted, label, secret, ciphertext)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// getXY gets the big-endian X/Y coordinates as full-length buffers.
func getXY(pub *ecdh.PublicKey) ([]byte, []byte) {
	rawPub := pub.Bytes()[1:]
	return rawPub[:len(rawPub)/2], rawPub[len(rawPub)/2:]
}
