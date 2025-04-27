package util

import (
	"bytes"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

func ValidateLabeledKEMTestVector(tpm transport.TPM, handle tpm2.NamedHandle, nameAlg tpm2.TPMIAlgHash, sym *tpm2.TPMTSymDefObject, restricted bool, label string, secret []byte, ciphertext []byte) (*string, error) {
	switch label {
	case "IDENTITY":
		if !restricted {
			// We can't test ActivateCredential on an unrestricted key.
			return nil, nil
		}
		return validateTestVectorUsingActivateCredential(tpm, handle, nameAlg, sym, label, secret, ciphertext)
	case "DUPLICATE":
		if !restricted {
			// We can't test Import on an unrestricted key.
			return nil, nil
		}
		return validateTestVectorUsingImport(tpm, handle, nameAlg, sym, label, secret, ciphertext)
	}

	return nil, nil
}

func validateTestVectorUsingActivateCredential(tpm transport.TPM, handle tpm2.NamedHandle, nameAlg tpm2.TPMIAlgHash, sym *tpm2.TPMTSymDefObject, label string, secret []byte, ciphertext []byte) (*string, error) {
	credentialPlaintext := []byte("TEST123")

	credential, err := CreateCredential(nameAlg, sym, handle.Name.Buffer, secret, credentialPlaintext)
	if err != nil {
		return nil, fmt.Errorf("creating credential: %w", err)
	}

	ac, err := tpm2.ActivateCredential{
		KeyHandle:      handle,
		ActivateHandle: handle,
		Secret:         tpm2.TPM2BEncryptedSecret{Buffer: ciphertext},
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

func validateTestVectorUsingImport(tpm transport.TPM, handle tpm2.NamedHandle, nameAlg tpm2.TPMIAlgHash, sym *tpm2.TPMTSymDefObject, label string, secret []byte, ciphertext []byte) (*string, error) {
	blobPlaintext := []byte("TEST123")
	blobObfuscate := make([]byte, 32)

	sealedPub, sealedPriv, err := MakeSealedBlob(tpm2.TPMAlgSHA256, blobObfuscate, blobPlaintext)
	if err != nil {
		return nil, fmt.Errorf("making sealed blob: %w", err)
	}
	sealedName, err := tpm2.ObjectName(sealedPub)
	if err != nil {
		return nil, fmt.Errorf("computing sealed blob name: %w", err)
	}
	duplicate, err := CreateDuplicate(nameAlg, sym, sealedName.Buffer, secret, sealedPriv)
	if err != nil {
		return nil, fmt.Errorf("making duplicate blob: %w", err)
	}

	impo, err := tpm2.Import{
		ParentHandle: handle,
		ObjectPublic: tpm2.New2B(*sealedPub),
		Duplicate:    tpm2.TPM2BPrivate{Buffer: duplicate},
		InSymSeed:    tpm2.TPM2BEncryptedSecret{Buffer: ciphertext},
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
