package util

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"errors"

	"github.com/google/go-tpm/tpm2"
)

// DeriveAndEncrypt derives a symmetric key and uses it to encrypt the plaintext.
func DeriveAndEncrypt(nameAlg tpm2.TPMIAlgHash, sym *tpm2.TPMTSymDefObject, seed []byte, context []byte, plaintext []byte) ([]byte, error) {
	// Only AES is supported.
	if sym.Algorithm != tpm2.TPMAlgAES {
		return nil, errors.New("only AES is supported")
	}
	mode, err := sym.Mode.AES()
	if err != nil {
		return nil, err
	}
	if *mode != tpm2.TPMAlgCFB {
		return nil, errors.New("only CFB is supported")
	}
	bits, err := sym.KeyBits.AES()
	if err != nil {
		return nil, err
	}

	hash, err := nameAlg.Hash()
	if err != nil {
		return nil, err
	}
	key, err := aes.NewCipher(tpm2.KDFa(hash, seed, "STORAGE", context, nil, int(*bits)))
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCFBEncrypter(key, make([]byte, key.BlockSize())).XORKeyStream(ciphertext, plaintext)
	return ciphertext, nil
}

// DeriveAndHMAC derives an HMAC key and uses it to HMAC the data, which can be provided in multiple chunks.
func DeriveAndHMAC(nameAlg tpm2.TPMIAlgHash, sym *tpm2.TPMTSymDefObject, seed []byte, data ...[]byte) ([]byte, error) {
	hash, err := nameAlg.Hash()
	if err != nil {
		return nil, err
	}
	key := tpm2.KDFa(hash, seed, "INTEGRITY", nil, nil, hash.Size()*8)
	hmac := hmac.New(hash.New, key)
	for _, data := range data {
		hmac.Write(data)
	}
	return hmac.Sum(nil), nil
}

// CreateCredential creates an encrypted secret that can be recovered using ActivateCredential as part of a key-attestation flow.
func CreateCredential(nameAlg tpm2.TPMIAlgHash, sym *tpm2.TPMTSymDefObject, name []byte, seed []byte, credentialValue []byte) (idObject []byte, err error) {
	// Marshal the credentialValue as a TPM2B_DIGEST before encrypting it.
	// See Part 1, "Credential Protection", and Part 2, "TPMS_ID_OBJECT".
	credential2B := tpm2.Marshal(tpm2.TPM2BDigest{Buffer: credentialValue})

	// Encrypt the credentialValue as encIdentity.
	encIdentity, err := DeriveAndEncrypt(nameAlg, sym, seed, name, credential2B)
	if err != nil {
		return nil, err
	}

	// Compute the HMAC of (encIdentity || name)
	identityHMAC, err := DeriveAndHMAC(nameAlg, sym, seed, nil, encIdentity, name)
	if err != nil {
		return nil, err
	}

	// Marshal the virtual TPMS_ID_OBJECT ourselves. We have to do this since encIdentity's size is encrypted.
	idObject = make([]byte, 0, 2+len(identityHMAC)+len(encIdentity))
	idObject = append(idObject, tpm2.Marshal(tpm2.TPM2BDigest{Buffer: identityHMAC})...)
	idObject = append(idObject, encIdentity...)

	return idObject, nil
}

// CreateDuplicate encrypts an object so that it can be imported under a target Storage Key.
// An inner wrapper is not supported.
func CreateDuplicate(nameAlg tpm2.TPMIAlgHash, sym *tpm2.TPMTSymDefObject, name []byte, seed []byte, sensitive []byte) (duplicate []byte, err error) {
	// Marshal the sensitive as a TPM2B_SENSITIVE before encrypting it.
	// See Part 1, "Outer Duplication Wrapper"
	sensitive2B := tpm2.Marshal(tpm2.TPM2BDigest{Buffer: sensitive})

	// Encrypt the sensitive2B as dupSensitive.
	dupSensitive, err := DeriveAndEncrypt(nameAlg, sym, seed, name, sensitive2B)
	if err != nil {
		return nil, err
	}

	// Compute the HMAC of (dupSensitive || name)
	outerHMAC, err := DeriveAndHMAC(nameAlg, sym, seed, nil, dupSensitive, name)
	if err != nil {
		return nil, err
	}

	// Marshal the virtual _PRIVATE ourselves. We have to do this since dupSensitive's size is encrypted.
	duplicate = make([]byte, 0, 2+len(outerHMAC)+len(dupSensitive))
	duplicate = append(duplicate, tpm2.Marshal(tpm2.TPM2BDigest{Buffer: outerHMAC})...)
	duplicate = append(duplicate, dupSensitive...)

	return duplicate, nil
}

// MakeSealedBlob creates a sealed blob object.
func MakeSealedBlob(nameAlg tpm2.TPMIAlgHash, obfuscation []byte, contents []byte) (*tpm2.TPMTPublic, []byte, error) {
	// Unique for a KEYEDHASH object is H_nameAlg(obfuscate | key)
	// See Part 1, "Public Area Creation"
	h, err := nameAlg.Hash()
	if err != nil {
		return nil, nil, err
	}
	uniqueHash := h.New()
	uniqueHash.Write(obfuscation)
	uniqueHash.Write(contents)
	public := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: nameAlg,
		ObjectAttributes: tpm2.TPMAObject{
			UserWithAuth: true,
			NoDA:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash, &tpm2.TPMSKeyedHashParms{}),
		Unique:     tpm2.NewTPMUPublicID(tpm2.TPMAlgKeyedHash, &tpm2.TPM2BDigest{Buffer: uniqueHash.Sum(nil)}),
	}
	sensitive := tpm2.TPMTSensitive{
		SensitiveType: tpm2.TPMAlgKeyedHash,
		SeedValue: tpm2.TPM2BDigest{
			Buffer: obfuscation,
		},
		Sensitive: tpm2.NewTPMUSensitiveComposite(tpm2.TPMAlgKeyedHash, &tpm2.TPM2BSensitiveData{
			Buffer: contents,
		}),
	}
	return &public, tpm2.Marshal(sensitive), nil
}
