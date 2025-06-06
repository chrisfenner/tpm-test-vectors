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
	Description      string
	Validated        *string `json:",omitempty"`
	Label            string
	EphemeralPrivate util.HexBytes
	PublicKey        util.HexBytes
	PrivateKey       util.HexBytes
	Secret           util.HexBytes
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
	var testDescription strings.Builder

	// Randomly decide whether to generate this key as Restricted.
	restricted := util.RandomBool()
	if restricted {
		testName.WriteString("R")
		testDescription.WriteString("restricted")
	} else {
		testName.WriteString("U")
		testDescription.WriteString("unrestricted")
	}

	curve := util.RandomCurve()
	fmt.Fprintf(&testName, "_%s", util.PrettyCurveName(curve))
	fmt.Fprintf(&testDescription, " ECC-%s key", util.PrettyCurveName(curve))

	nameAlg := util.RandomHashAlg()
	fmt.Fprintf(&testName, "_%s", util.PrettyAlgName(nameAlg))
	fmt.Fprintf(&testDescription, " using name alg %s,", util.PrettyAlgName(nameAlg))
	hashAlg := nameAlg

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
		symmetric = tpm2.TPMTSymDefObject{
			Algorithm: tpm2.TPMAlgNull,
		}

		// Randomly decide whether to make an unrestricted key say that it uses MQV instead of ECDH.
		// This has no effect on the Labeled KEM: it always uses ECDH.
		if util.RandomBool() {
			scheme = tpm2.TPMTECCScheme{
				Scheme: tpm2.TPMAlgECDH,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDH, &tpm2.TPMSKeySchemeECDH{
					HashAlg: hashAlg,
				}),
			}
		} else {
			scheme = tpm2.TPMTECCScheme{
				Scheme: tpm2.TPMAlgECMQV,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECMQV, &tpm2.TPMSKeySchemeECMQV{
					HashAlg: hashAlg,
				}),
			}
		}
		schemeAlg = hashAlg
		fmt.Fprintf(&testName, "_%s_%s", util.PrettyAlgName(scheme.Scheme), util.PrettyAlgName(schemeAlg))
		fmt.Fprintf(&testDescription, " with ECC scheme %s using hash alg %s", util.PrettyAlgName(scheme.Scheme), util.PrettyAlgName(schemeAlg))
	} else {
		fmt.Fprintf(&testName, "_%d", keyBits)
		fmt.Fprintf(&testDescription, " with symmetric scheme AES-CFB-%d", keyBits)
	}

	nameAlgHash, err := nameAlg.Hash()
	if err != nil {
		return nil, err
	}

	// Generate the key in the TPM simulator.
	cp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:       tpm2.TPMAlgECC,
			NameAlg:    nameAlg,
			AuthPolicy: util.DuplicatePolicy(nameAlg),
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

	// Export the private key created by the TPM simulator.
	priv, err := util.Duplicate(tpm, nameAlg, tpm2.NamedHandle{
		Handle: cp.ObjectHandle,
		Name:   cp.Name,
	})
	if err != nil {
		return nil, err
	}

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

	result := TestVector{
		Name:             testName.String(),
		Description:      testDescription.String(),
		Label:            label,
		EphemeralPrivate: ephemeralPriv.Bytes(),
		PublicKey:        cp.OutPublic.Bytes(),
		PrivateKey:       priv,
		Secret:           secret,
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
