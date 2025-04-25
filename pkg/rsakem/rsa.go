// Package labeledencaps generates test vectors for the labeled encapsulation ("Secret Sharing") function from TPM 2.0.
package rsakem

import (
	cryptorand "crypto/rand"
	"fmt"
	"math/rand"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

type TestVector struct {
	PublicKey  []byte
	Label      string
	Secret     []byte
	Ciphertext []byte
}

var hashes = []tpm2.TPMIAlgHash{
	tpm2.TPMAlgSHA1,
	tpm2.TPMAlgSHA256,
	tpm2.TPMAlgSHA384,
}

func randomHashAlg() tpm2.TPMIAlgHash {
	idx := rand.Intn(len(hashes))
	return hashes[idx]
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

var keyBits = []tpm2.TPMKeyBits{
	128,
	256,
}

func randomKeyBits() tpm2.TPMKeyBits {
	idx := rand.Intn(len(keyBits))
	return keyBits[idx]
}

var rsaBits = []tpm2.TPMIRSAKeyBits{
	2048,
	3072,
	4096,
}

func randomRSABits() tpm2.TPMIRSAKeyBits {
	idx := rand.Intn(len(rsaBits))
	return rsaBits[idx]
}

// GenerateTestVector generates an RSA Labeled Encapsulation test vector.
func GenerateTestVector(tpm transport.TPM) (*TestVector, error) {
	// Generate a random RSA restricted decryption key.
	// Randomly choose TPM_ALG_NULL or OAEP for the scheme.
	scheme := tpm2.TPMTRSAScheme{
		Scheme: tpm2.TPMAlgNull,
	}
	template := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: randomHashAlg(),
		ObjectAttributes: tpm2.TPMAObject{
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			AdminWithPolicy:     false,
			NoDA:                true,
			Restricted:          true,
			Decrypt:             true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &tpm2.TPMSRSAParms{
			Symmetric: tpm2.TPMTSymDefObject{
				Algorithm: tpm2.TPMAlgAES,
				KeyBits: tpm2.NewTPMUSymKeyBits(
					tpm2.TPMAlgAES,
					randomKeyBits(),
				),
				Mode: tpm2.NewTPMUSymMode(
					tpm2.TPMAlgAES,
					tpm2.TPMAlgCFB,
				),
			},
			Scheme:  scheme,
			KeyBits: randomRSABits(),
		}),
	}
	fmt.Printf("Template: %+v\n", template)

	cp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(template),
	}.Execute(tpm)
	if err != nil {
		return nil, err
	}
	defer tpm2.FlushContext{FlushHandle: cp.ObjectHandle}.Execute(tpm)

	pub, err := cp.OutPublic.Contents()
	if err != nil {
		return nil, err
	}

	kem, err := tpm2.ImportEncapsulationKey(pub)
	if err != nil {
		return nil, err
	}
	label := randomLabel()
	secret, ct, err := kem.Encapsulate(cryptorand.Reader, label)
	if err != nil {
		return nil, err
	}

	return &TestVector{
		PublicKey:  cp.OutPublic.Bytes(),
		Label:      label,
		Secret:     secret,
		Ciphertext: ct,
	}, nil
}
