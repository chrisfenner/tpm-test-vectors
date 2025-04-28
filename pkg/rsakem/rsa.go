// Package rsakem generates test vectors for the labeled encapsulation ("Secret Sharing") function from TPM 2.0.
package rsakem

import (
	"bytes"
	"crypto/rsa"
	"fmt"
	"math/rand"
	"strings"

	"github.com/chrisfenner/tpm-test-vectors/pkg/util"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

var rsaBits = []tpm2.TPMIRSAKeyBits{
	2048,
	3072,
	4096,
}

func randomRSABits() tpm2.TPMIRSAKeyBits {
	idx := rand.Intn(len(rsaBits))
	return rsaBits[idx]
}

type TestVector struct {
	Name        string
	Description string
	Validated   *string `json:",omitempty"`
	Label       string
	OAEPSalt    util.HexBytes
	PublicKey   util.HexBytes
	Secret      util.HexBytes
	Ciphertext  util.HexBytes
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
	rsaSize := randomRSABits()
	fmt.Fprintf(&testName, "_%d", rsaSize)
	fmt.Fprintf(&testDescription, " RSA-%d key", rsaSize)

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
	scheme := tpm2.TPMTRSAScheme{
		Scheme: tpm2.TPMAlgNull,
	}
	schemeAlg := tpm2.TPMAlgNull
	if !restricted {
		hashAlg = util.RandomHashAlg()
		fmt.Fprintf(&testName, "_%s", util.PrettyAlgName(hashAlg))
		fmt.Fprintf(&testDescription, " with %s for OAEP", util.PrettyAlgName(hashAlg))

		symmetric = tpm2.TPMTSymDefObject{
			Algorithm: tpm2.TPMAlgNull,
		}
		scheme = tpm2.TPMTRSAScheme{
			Scheme: tpm2.TPMAlgOAEP,
			Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgOAEP, &tpm2.TPMSEncSchemeOAEP{
				HashAlg: hashAlg,
			}),
		}
		schemeAlg = hashAlg
	} else {
		fmt.Fprintf(&testName, "_%d", keyBits)
		fmt.Fprintf(&testDescription, " with symmetric scheme AES-CFB-%d", keyBits)
	}

	hashAlgHash, err := hashAlg.Hash()
	if err != nil {
		return nil, err
	}

	// Generate the key in the TPM simulator.
	cp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgRSA,
			NameAlg: nameAlg,
			ObjectAttributes: tpm2.TPMAObject{
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
				AdminWithPolicy:     false,
				NoDA:                true,
				Decrypt:             true,
				Restricted:          restricted,
			},
			Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &tpm2.TPMSRSAParms{
				Symmetric: symmetric,
				Scheme:    scheme,
				KeyBits:   rsaSize,
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
	rsaParms, err := pub.Parameters.RSADetail()
	if err != nil {
		return nil, err
	}
	rsaUnique, err := pub.Unique.RSA()
	if err != nil {
		return nil, err
	}
	rsaPub, err := tpm2.RSAPub(rsaParms, rsaUnique)
	if err != nil {
		return nil, err
	}

	// Generate a random OAEP salt and secret value.
	// The size of both values depends on the hash alg used for OAEP (which is always nameAlg in the case of Restricted keys).
	// NOTE: This is different than ECC, in which the scheme hash algorithm is always ignored.
	salt := util.RandomBytes(hashAlgHash.Size())
	secret := util.RandomBytes(hashAlgHash.Size())
	label := util.RandomEncapsulationLabel()
	ciphertext, err := rsa.EncryptOAEP(hashAlgHash.New(), bytes.NewReader(salt), rsaPub, secret, util.FormatLabel(label))
	if err != nil {
		return nil, err
	}

	result := TestVector{
		Name:        testName.String(),
		Description: testDescription.String(),
		Label:       label,
		OAEPSalt:    salt,
		PublicKey:   cp.OutPublic.Bytes(),
		Secret:      secret,
		Ciphertext:  ciphertext,
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
