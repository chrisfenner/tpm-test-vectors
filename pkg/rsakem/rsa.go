// Package labeledencaps generates test vectors for the labeled encapsulation ("Secret Sharing") function from TPM 2.0.
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
	Name       string
	Validated  *string `json:",omitempty"`
	Label      string
	OAEPSalt   util.HexBytes
	Secret     util.HexBytes
	PublicKey  util.HexBytes
	Ciphertext util.HexBytes
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

	rsaSize := randomRSABits()
	fmt.Fprintf(&testName, "%d_", rsaSize)

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
	scheme := tpm2.TPMTRSAScheme{
		Scheme: tpm2.TPMAlgNull,
	}
	if !restricted {
		hashAlg = util.RandomHashAlg()
		fmt.Fprintf(&testName, "%s_", util.PrettyAlgName(hashAlg))

		symmetric = tpm2.TPMTSymDefObject{
			Algorithm: tpm2.TPMAlgNull,
		}
		scheme = tpm2.TPMTRSAScheme{
			Scheme: tpm2.TPMAlgOAEP,
			Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgOAEP, &tpm2.TPMSEncSchemeOAEP{
				HashAlg: hashAlg,
			}),
		}
	} else {
		fmt.Fprintf(&testName, "%d_", keyBits)
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
	salt := util.RandomBytes(hashAlgHash.Size())
	secret := util.RandomBytes(hashAlgHash.Size())
	label := util.RandomEncapsulationLabel()
	ciphertext, err := rsa.EncryptOAEP(hashAlgHash.New(), bytes.NewReader(salt), rsaPub, secret, util.FormatLabel(label))
	if err != nil {
		return nil, err
	}

	if restricted {
		testName.WriteString("restricted")
	} else {
		testName.WriteString("unrestricted")
	}

	result := TestVector{
		Name:       testName.String(),
		Label:      label,
		OAEPSalt:   salt,
		Secret:     secret,
		PublicKey:  cp.OutPublic.Bytes(),
		Ciphertext: ciphertext,
	}

	result.Validated, err = validateTestVector(tpm, tpm2.NamedHandle{
		Handle: cp.ObjectHandle,
		Name:   cp.Name,
	}, pub.NameAlg, &symmetric, restricted, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

func validateTestVector(tpm transport.TPM, handle tpm2.NamedHandle, nameAlg tpm2.TPMIAlgHash, sym *tpm2.TPMTSymDefObject, restricted bool, vector *TestVector) (*string, error) {
	switch vector.Label {
	case "IDENTITY":
		if !restricted {
			// We can't test ActivateCredential on an unrestricted key.
			return nil, nil
		}
		return validateTestVectorUsingActivateCredential(tpm, handle, nameAlg, sym, vector)
	case "DUPLICATE":
		if !restricted {
			// We can't test Import on an unrestricted key.
			return nil, nil
		}
		return validateTestVectorUsingImport(tpm, handle, nameAlg, sym, vector)
	}

	return nil, nil
}

func validateTestVectorUsingActivateCredential(tpm transport.TPM, handle tpm2.NamedHandle, nameAlg tpm2.TPMIAlgHash, sym *tpm2.TPMTSymDefObject, vector *TestVector) (*string, error) {
	credentialPlaintext := []byte("TEST123")

	credential, err := util.CreateCredential(nameAlg, sym, handle.Name.Buffer, vector.Secret, credentialPlaintext)
	if err != nil {
		return nil, fmt.Errorf("creating credential: %w", err)
	}

	ac, err := tpm2.ActivateCredential{
		KeyHandle:      handle,
		ActivateHandle: handle,
		Secret:         tpm2.TPM2BEncryptedSecret{Buffer: vector.Ciphertext},
		CredentialBlob: tpm2.TPM2BIDObject{Buffer: credential},
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("activating credential: %w", err)
	}

	if !bytes.Equal(ac.CertInfo.Buffer, credentialPlaintext) {
		return nil, fmt.Errorf("want %x got %x", credentialPlaintext, ac.CertInfo.Buffer)
	}
	validation := "TPM2_ActivateCredential"
	return &validation, nil
}

func validateTestVectorUsingImport(tpm transport.TPM, handle tpm2.NamedHandle, nameAlg tpm2.TPMIAlgHash, sym *tpm2.TPMTSymDefObject, vector *TestVector) (*string, error) {
	blobPlaintext := []byte("TEST123")
	blobObfuscate := make([]byte, 32)

	sealedPub, sealedPriv, err := util.MakeSealedBlob(tpm2.TPMAlgSHA256, blobObfuscate, blobPlaintext)
	if err != nil {
		return nil, fmt.Errorf("making sealed blob: %w", err)
	}
	sealedName, err := tpm2.ObjectName(sealedPub)
	if err != nil {
		return nil, fmt.Errorf("computing sealed blob name: %w", err)
	}
	duplicate, err := util.CreateDuplicate(nameAlg, sym, sealedName.Buffer, vector.Secret, sealedPriv)
	if err != nil {
		return nil, fmt.Errorf("making duplicate blob: %w", err)
	}

	impo, err := tpm2.Import{
		ParentHandle: handle,
		ObjectPublic: tpm2.New2B(*sealedPub),
		Duplicate:    tpm2.TPM2BPrivate{Buffer: duplicate},
		InSymSeed:    tpm2.TPM2BEncryptedSecret{Buffer: vector.Ciphertext},
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("importing sealed blob: %w", err)
	}

	load, err := tpm2.Load{
		ParentHandle: handle,
		InPublic:     tpm2.New2B(*sealedPub),
		InPrivate:    impo.OutPrivate,
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("loading sealed blob: %w", err)
	}
	defer tpm2.FlushContext{FlushHandle: load.ObjectHandle}.Execute(tpm)

	unseal, err := tpm2.Unseal{
		ItemHandle: tpm2.NamedHandle{
			Handle: load.ObjectHandle,
			Name:   *sealedName,
		},
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("unsealing sealed blob: %w", err)
	}

	if !bytes.Equal(unseal.OutData.Buffer, blobPlaintext) {
		return nil, fmt.Errorf("want %x got %x", blobPlaintext, unseal.OutData.Buffer)
	}
	validation := "TPM2_Import"
	return &validation, nil
}
