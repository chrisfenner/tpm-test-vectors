package util

import (
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// MockAuditSession is for testing session crypto with audit sessions with a known SessionKey.
// Copied extensively from https://github.com/google/go-tpm/blob/main/tpm2/sessions.go.
type MockAuditSession struct {
	Hash        tpm2.TPMIAlgHash
	HandleValue tpm2.TPMHandle
	SessionKey  []byte
	CallerNonce tpm2.TPM2BNonce
	TPMNonce    tpm2.TPM2BNonce
}

var _ tpm2.Session = &MockAuditSession{}

var mockAttributes = tpm2.TPMASession{
	ContinueSession: true,
	Audit:           true,
}

func (s *MockAuditSession) Init(tpm transport.TPM) error {
	return nil
}

func (s *MockAuditSession) CleanupFailure(tpm transport.TPM) error {
	return nil
}

func (s *MockAuditSession) NonceTPM() tpm2.TPM2BNonce {
	return s.TPMNonce
}

func (s *MockAuditSession) NewNonceCaller() error {
	// This implementation always uses the same NonceCaller.
	return nil
}

// Authorize computes the authorization structure for the session.
// Unlike the TPM spec, authIndex is zero-based.
func (s *MockAuditSession) Authorize(cc tpm2.TPMCC, parms, addNonces []byte, names []tpm2.TPM2BName, authIndex int) (*tpm2.TPMSAuthCommand, error) {
	// Part 1, 19.6
	// HMAC key is (sessionKey || auth) unless this session is authorizing
	// its bind target
	var hmacKey []byte
	hmacKey = append(hmacKey, s.SessionKey...)

	// Compute the authorization HMAC.
	cph, err := cpHash(s.Hash, cc, names, parms)
	if err != nil {
		return nil, err
	}
	hmac, err := computeHMAC(s.Hash, hmacKey, cph, s.CallerNonce.Buffer, s.TPMNonce.Buffer, addNonces, mockAttributes)
	if err != nil {
		return nil, err
	}
	result := tpm2.TPMSAuthCommand{
		Handle:     s.HandleValue,
		Nonce:      s.CallerNonce,
		Attributes: mockAttributes,
		Authorization: tpm2.TPM2BData{
			Buffer: hmac,
		},
	}
	return &result, nil
}

// Validate validates the response session structure for the session.
// It updates nonceTPM from the TPM's response.
func (s *MockAuditSession) Validate(rc tpm2.TPMRC, cc tpm2.TPMCC, parms []byte, names []tpm2.TPM2BName, authIndex int, auth *tpm2.TPMSAuthResponse) error {
	// Track the new nonceTPM for the session.
	s.TPMNonce = auth.Nonce

	// Part 1, 19.6
	// HMAC key is (sessionKey || auth) unless this session is authorizing
	// its bind target
	var hmacKey []byte
	hmacKey = append(hmacKey, s.SessionKey...)

	// Compute the authorization HMAC.
	rph, err := rpHash(s.Hash, rc, cc, parms)
	if err != nil {
		return err
	}
	mac, err := computeHMAC(s.Hash, hmacKey, rph, s.TPMNonce.Buffer, s.CallerNonce.Buffer, nil, auth.Attributes)
	if err != nil {
		return err
	}
	// Compare the HMAC (constant time)
	if !hmac.Equal(mac, auth.Authorization.Buffer) {
		return fmt.Errorf("incorrect authorization HMAC")
	}
	return nil
}

func (s *MockAuditSession) IsEncryption() bool {
	return false
}

func (s *MockAuditSession) IsDecryption() bool {
	return false
}

func (s *MockAuditSession) Encrypt(parameter []byte) error {
	return errors.New("TODO")
}

func (s *MockAuditSession) Decrypt(parameter []byte) error {
	return errors.New("TODO")
}

func (s *MockAuditSession) Handle() tpm2.TPMHandle {
	return s.HandleValue
}

// cpHash calculates the TPM command parameter hash.
// cpHash = hash(CC || names || parms)
func cpHash(alg tpm2.TPMIAlgHash, cc tpm2.TPMCC, names []tpm2.TPM2BName, parms []byte) ([]byte, error) {
	ha, err := alg.Hash()
	if err != nil {
		return nil, err
	}
	h := ha.New()
	binary.Write(h, binary.BigEndian, cc)
	for _, name := range names {
		h.Write(name.Buffer)
	}
	h.Write(parms)
	return h.Sum(nil), nil
}

// rpHash calculates the TPM response parameter hash.
// rpHash = hash(RC || CC || parms)
func rpHash(alg tpm2.TPMIAlgHash, rc tpm2.TPMRC, cc tpm2.TPMCC, parms []byte) ([]byte, error) {
	ha, err := alg.Hash()
	if err != nil {
		return nil, err
	}
	h := ha.New()
	binary.Write(h, binary.BigEndian, rc)
	binary.Write(h, binary.BigEndian, cc)
	h.Write(parms)
	return h.Sum(nil), nil
}

// computeHMAC computes an authorization HMAC according to various equations in
// Part 1.
// This applies to both commands and responses.
// The value of key depends on whether the session is bound and/or salted.
// pHash cpHash for a command, or an rpHash for a response.
// nonceNewer in a command is the new nonceCaller sent in the command session packet.
// nonceNewer in a response is the new nonceTPM sent in the response session packet.
// nonceOlder in a command is the last nonceTPM sent by the TPM for this session.
// This may be when the session was created, or the last time it was used.
// nonceOlder in a response is the corresponding nonceCaller sent in the command.
func computeHMAC(alg tpm2.TPMIAlgHash, key, pHash, nonceNewer, nonceOlder, addNonces []byte, attrs tpm2.TPMASession) ([]byte, error) {
	ha, err := alg.Hash()
	if err != nil {
		return nil, err
	}
	mac := hmac.New(ha.New, key)
	mac.Write(pHash)
	mac.Write(nonceNewer)
	mac.Write(nonceOlder)
	mac.Write(addNonces)
	mac.Write(attrsToBytes(attrs))
	return mac.Sum(nil), nil
}

func attrsToBytes(attrs tpm2.TPMASession) []byte {
	var res byte
	if attrs.ContinueSession {
		res |= (1 << 0)
	}
	if attrs.AuditExclusive {
		res |= (1 << 1)
	}
	if attrs.AuditReset {
		res |= (1 << 2)
	}
	if attrs.Decrypt {
		res |= (1 << 5)
	}
	if attrs.Encrypt {
		res |= (1 << 6)
	}
	if attrs.Audit {
		res |= (1 << 7)
	}
	return []byte{res}
}
