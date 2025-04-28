package util

import (
	"bytes"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

func ValidateLabeledKEMTestVector(tpm transport.TPM, handle tpm2.NamedHandle, nameAlg tpm2.TPMIAlgHash, schemeAlg tpm2.TPMIAlgHash, sym *tpm2.TPMTSymDefObject, restricted bool, label string, secret []byte, ciphertext []byte) (*string, error) {
	switch label {
	case "IDENTITY":
		if !restricted {
			// We can't test ActivateCredential on an unrestricted key.
			return nil, nil
		}
		return validateTestVectorUsingActivateCredential(tpm, handle, nameAlg, sym, secret, ciphertext)
	case "DUPLICATE":
		if !restricted {
			// We can't test Import on an unrestricted key.
			return nil, nil
		}
		return validateTestVectorUsingImport(tpm, handle, nameAlg, sym, secret, ciphertext)
	case "SECRET":
		// We can test StartAuthSession on restricted or unrestricted keys.
		return validateTestVectorUsingStartAuthSession(tpm, handle, nameAlg, schemeAlg, secret, ciphertext)
	}

	return nil, nil
}

func validateTestVectorUsingActivateCredential(tpm transport.TPM, handle tpm2.NamedHandle, nameAlg tpm2.TPMIAlgHash, sym *tpm2.TPMTSymDefObject, secret []byte, ciphertext []byte) (*string, error) {
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

func validateTestVectorUsingImport(tpm transport.TPM, handle tpm2.NamedHandle, nameAlg tpm2.TPMIAlgHash, sym *tpm2.TPMTSymDefObject, secret []byte, ciphertext []byte) (*string, error) {
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

func validateTestVectorUsingStartAuthSession(tpm transport.TPM, handle tpm2.NamedHandle, nameAlg tpm2.TPMIAlgHash, schemeAlg tpm2.TPMIAlgHash, secret []byte, ciphertext []byte) (*string, error) {
	hashAlg := nameAlg
	if schemeAlg == tpm2.TPMAlgNull {
		hashAlg = nameAlg
	}

	nonceCaller := make([]byte, 16)
	algHash, err := hashAlg.Hash()
	if err != nil {
		return nil, err
	}

	sas, err := tpm2.StartAuthSession{
		TPMKey:        handle,
		SessionType:   tpm2.TPMSEHMAC,
		AuthHash:      hashAlg,
		EncryptedSalt: tpm2.TPM2BEncryptedSecret{Buffer: ciphertext},
		NonceCaller:   tpm2.TPM2BNonce{Buffer: nonceCaller},
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("starting auth session: %w", err)
	}
	defer tpm2.FlushContext{
		FlushHandle: sas.SessionHandle,
	}.Execute(tpm)

	// Use the salted session as an audit session to read the TPM manufacturer ID.
	mockSession := MockAuditSession{
		Hash:        hashAlg,
		HandleValue: sas.SessionHandle,
		SessionKey:  tpm2.KDFa(algHash, secret, "ATH", sas.NonceTPM.Buffer, nonceCaller, algHash.Size()*8),
		CallerNonce: tpm2.TPM2BNonce{Buffer: nonceCaller},
		TPMNonce:    sas.NonceTPM,
	}

	_, err = tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTManufacturer),
		PropertyCount: 1,
	}.Execute(tpm, &mockSession)
	if err != nil {
		return nil, fmt.Errorf("calling GetCapability using salted audit session: %w", err)
	}

	validation := "TPM2_StartAuthSession"
	return &validation, nil
}
