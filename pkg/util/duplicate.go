package util

import (
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

func DuplicatePolicy(nameAlg tpm2.TPMIAlgHash) tpm2.TPM2BDigest {
	calc, err := tpm2.NewPolicyCalculator(nameAlg)
	if err != nil {
		panic(fmt.Sprintf("failed to create PolicyCalculator using alg %v: %v", nameAlg, err))
	}
	err = tpm2.PolicyCommandCode{
		Code: tpm2.TPMCCDuplicate,
	}.Update(calc)
	if err != nil {
		panic(fmt.Sprintf("failed to update PolicyCalculator: %v", err))
	}
	return tpm2.TPM2BDigest{Buffer: calc.Hash().Digest}
}

func Duplicate(tpm transport.TPM, nameAlg tpm2.TPMIAlgHash, handle tpm2.NamedHandle) ([]byte, error) {
	dup, err := tpm2.Duplicate{
		ObjectHandle: tpm2.AuthHandle{
			Handle: handle.Handle,
			Name:   handle.Name,
			Auth: tpm2.Policy(nameAlg, 16, func(tpm transport.TPM, handle tpm2.TPMISHPolicy, nonceTPM tpm2.TPM2BNonce) error {
				_, err := tpm2.PolicyCommandCode{
					PolicySession: handle,
					Code:          tpm2.TPMCCDuplicate,
				}.Execute(tpm)
				return err
			}),
		},
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to duplicate: %w", err)
	}

	// This gets us a TPM2B_PRIVATE wrapping a _PRIVATE with no inner or outer
	// integrity. Unmarshal the contents as a TPM2B_SENSITIVE and then give the
	// contents.
	sens, err := tpm2.Unmarshal[tpm2.TPM2BSensitive](dup.Duplicate.Buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshla TPM2B_SENSITIVE: %w", err)
	}
	return sens.Bytes(), nil
}
