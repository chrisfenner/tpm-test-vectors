package util

import (
	"fmt"

	"github.com/google/go-tpm/tpm2"
)

func PrettyAlgName(alg tpm2.TPMAlgID) string {
	switch alg {
	case tpm2.TPMAlgRSA:
		return "RSA"
	case tpm2.TPMAlgTDES:
		return "TDES"
	case tpm2.TPMAlgSHA1:
		return "SHA1"
	case tpm2.TPMAlgHMAC:
		return "HMAC"
	case tpm2.TPMAlgAES:
		return "AES"
	case tpm2.TPMAlgMGF1:
		return "MGF1"
	case tpm2.TPMAlgKeyedHash:
		return "KeyedHash"
	case tpm2.TPMAlgXOR:
		return "XOR"
	case tpm2.TPMAlgSHA256:
		return "SHA256"
	case tpm2.TPMAlgSHA384:
		return "SHA384"
	case tpm2.TPMAlgSHA512:
		return "SHA512"
	case tpm2.TPMAlgSHA256192:
		return "SHA256192"
	case tpm2.TPMAlgNull:
		return "Null"
	case tpm2.TPMAlgSM3256:
		return "SM3256"
	case tpm2.TPMAlgSM4:
		return "SM4"
	case tpm2.TPMAlgRSASSA:
		return "RSASSA"
	case tpm2.TPMAlgRSAES:
		return "RSAES"
	case tpm2.TPMAlgRSAPSS:
		return "RSAPSS"
	case tpm2.TPMAlgOAEP:
		return "OAEP"
	case tpm2.TPMAlgECDSA:
		return "ECDSA"
	case tpm2.TPMAlgECDH:
		return "ECDH"
	case tpm2.TPMAlgECDAA:
		return "ECDAA"
	case tpm2.TPMAlgSM2:
		return "SM2"
	case tpm2.TPMAlgECSchnorr:
		return "ECSchnorr"
	case tpm2.TPMAlgECMQV:
		return "ECMQV"
	case tpm2.TPMAlgKDF1SP80056A:
		return "KDF1SP80056A"
	case tpm2.TPMAlgKDF2:
		return "KDF2"
	case tpm2.TPMAlgKDF1SP800108:
		return "KDF1SP800108"
	case tpm2.TPMAlgECC:
		return "ECC"
	case tpm2.TPMAlgSymCipher:
		return "SymCipher"
	case tpm2.TPMAlgCamellia:
		return "Camellia"
	case tpm2.TPMAlgSHA3256:
		return "SHA3256"
	case tpm2.TPMAlgSHA3384:
		return "SHA3384"
	case tpm2.TPMAlgSHA3512:
		return "SHA3512"
	case tpm2.TPMAlgSHAKE128:
		return "SHAKE128"
	case tpm2.TPMAlgSHAKE256:
		return "SHAKE256"
	case tpm2.TPMAlgSHAKE256192:
		return "SHAKE256192"
	case tpm2.TPMAlgSHAKE256256:
		return "SHAKE256256"
	case tpm2.TPMAlgSHAKE256512:
		return "SHAKE256512"
	case tpm2.TPMAlgCMAC:
		return "CMAC"
	case tpm2.TPMAlgCTR:
		return "CTR"
	case tpm2.TPMAlgOFB:
		return "OFB"
	case tpm2.TPMAlgCBC:
		return "CBC"
	case tpm2.TPMAlgCFB:
		return "CFB"
	case tpm2.TPMAlgECB:
		return "ECB"
	case tpm2.TPMAlgCCM:
		return "CCM"
	case tpm2.TPMAlgGCM:
		return "GCM"
	case tpm2.TPMAlgKW:
		return "KW"
	case tpm2.TPMAlgKWP:
		return "KWP"
	case tpm2.TPMAlgEAX:
		return "EAX"
	case tpm2.TPMAlgEDDSA:
		return "EDDSA"
	case tpm2.TPMAlgEDDSAPH:
		return "EDDSAPH"
	case tpm2.TPMAlgLMS:
		return "LMS"
	case tpm2.TPMAlgXMSS:
		return "XMSS"
	case tpm2.TPMAlgKEYEDXOF:
		return "KEYEDXOF"
	case tpm2.TPMAlgKMACXOF128:
		return "KMACXOF128"
	case tpm2.TPMAlgKMACXOF256:
		return "KMACXOF256"
	case tpm2.TPMAlgKMAC128:
		return "KMAC128"
	case tpm2.TPMAlgKMAC256:
		return "KMAC256"
	}
	return fmt.Sprintf("%04x", uint16(alg))
}

func PrettyCurveName(curve tpm2.TPMECCCurve) string {
	switch curve {
	case tpm2.TPMECCNone:
		return "None"
	case tpm2.TPMECCNistP192:
		return "P192"
	case tpm2.TPMECCNistP224:
		return "P224"
	case tpm2.TPMECCNistP256:
		return "P256"
	case tpm2.TPMECCNistP384:
		return "P384"
	case tpm2.TPMECCNistP521:
		return "P521"
	case tpm2.TPMECCBNP256:
		return "BNP256"
	case tpm2.TPMECCBNP638:
		return "BNP638"
	case tpm2.TPMECCSM2P256:
		return "SM2P256"
	case tpm2.TPMECCBrainpoolP256R1:
		return "BrainpoolP256R1"
	case tpm2.TPMECCBrainpoolP384R1:
		return "BrainpoolP384R1"
	case tpm2.TPMECCBrainpoolP512R1:
		return "BrainpoolP512R1"
	case tpm2.TPMECCCurve25519:
		return "Curve25519"
	case tpm2.TPMECCCurve448:
		return "Curve448"
	}
	return fmt.Sprintf("%04x", uint16(curve))
}
