# tpm-test-vectors
Test vectors for TPM crypto.

# Status of this project

Current status: Ready for use. Tested against go-tpm.

Creating a new suite of test vectors for an existing cryptographic protocol
should be done carefully. Proposed test vectors need to be validated against
at least one (ideally multiple) existing known-good implementations of the
protocol. Existing implementations do not always have the necessary hooks for
testing.

This generator is based on [go-tpm](https://github.com/google/go-tpm), which
contains a fairly mature crypto protocol implementation (at least for KDFa and
KDFe).

# Generator Usage

The test vector generation tool uses a running TPM simulator to help validate
its outputs in some cases.

```sh
go run cmd/generate.test.go --count ${COUNT} --kind ${KIND} --tpm_cmd_port ${PORT} --tpm_plat_port ${PORT}
```

* `$COUNT` is a positive integer, the number of test vectors to generate
* `$KIND` selects the test vector type, and is one of:
  * kdfa
  * kdfe
  * rsa_labeled_encaps
  * ecc_labeled_encaps
* `$PORT` is the cmd/plat port for a running TPM simulator (default 2321/2322)

## Output

The output is a test-vector-type dependent JSON blob containing the test data.
Binary data is encoded in hexadecimal.

# Test Vectors

The test vectors from this project are meant for validating a TPM or TPM client
library's implementation of TPM crypto protocols (KDFa, KDFe, and Secret
Sharing).

Testing KDFa and KDFe is fairly straightforward, as these functions have clear
and distinct inputs and outputs.

For the labeled encapsulation (ECC/RSA Secret Sharing) cases, the target
library needs to be designed with testability in mind. Both these protocols
incorporate a source of randomness to generate a pair (shared secret,
ciphertext). A useful pattern to implementors is to have an internal
"derandomized" implementation of the encapsulation (see:
[X-Wing](https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-01.html)).

## KDFa

KDFa test vectors correspond to "KDFa" from the TPM 2.0 Specification (Part 1).

Example:

```json
"Name": "27_SHA256_116",
"HashAlg": 11,
"Key": "aff14e568afc0ea51eea748c8915df067c7700",
"Label": "IDENTITY",
"ContextU": "ce4edfb881540700e300",
"ContextV": "68ddb4a0e59d74cd34dfe631d91e1ea3fbc95865440adedff7e9d011890fba",
"Bits": 116,
"Result": "019ed5e0956338ddda4413ecee5cf2"
```

### Name

Type: string

Short name of the test case, including the hash algorithm and bits of output.

### HashAlg

Type: integer

TPM alg ID corresponding to the hash algorithm that was used.

### Key

Type: binary (encoded as hex string)

KDF key.

### Label

Type: string

Label used in KDFa. Note that KDFa includes the trailing `NUL`.

### ContextU

Type: binary (encoded as hex string)

Context data.

### ContextV

Type: binary (encoded as hex string)

Context data.

### Bits

Type: integer

Requested number of bits of output. 

### Result

Type: binary (encoded as hex string)

Resulting value. Note that if *bits* is not a multiple of 8, the result is
left-padded with 0's according to the TPM Specification.

## KDFe

KDFe test vectors correspond to "KDFe" from the TPM 2.0 Specification (Part 1).

Example:

```json
"Name": "33_SHA256_215",
"HashAlg": 11,
"Z": "ffcead5817fa51",
"Label": "OBFUSCATE",
"ContextU": "3a25c7420a6ea094aff570c12fd40d2b8eff",
"ContextV": "8505ad0684d7196c4153860ece58c62c20fa07f18fff",
"Bits": 215,
"Result": "7e20d953e93f3760753b0aeba83c1114c440493bd8101f12665868"
```

### Name

Type: string

Short name of the test case, including the hash algorithm and bits of output.

### HashAlg

Type: integer

TPM alg ID corresponding to the hash algorithm that was used.

### Z

Type: binary (encoded as hex string)

Shared secret (e.g., an ECDH X-value)

### Label

Type: string

Label used in KDFe. Note that KDFe includes the trailing `NUL`.

### ContextU

Type: binary (encoded as hex string)

Context data.

### ContextV

Type: binary (encoded as hex string)

Context data.

### Bits

Type: integer

Requested number of bits of output. 

### Result

Type: binary (encoded as hex string)

Resulting value. Note that if *bits* is not a multiple of 8, the result is
left-padded with 0's according to the TPM Specification.

## ecc_labeled_encaps

ECC Labeled Encapsulation test vectors correspond to ECDH Secret Sharing
operations from the TPM 2.0 Specification (Part 1).

Note that ECC Labeled Encapsulation ignores the target key's ECDH scheme (along
with any parameters) and always uses ECDH and with *nameAlg* of the target
public key for KDFe.

An implementation of "derandomized" ECC Labeled Encapsulation will need to take
the random ephemeral ECDH private key (*d*) along with the label and public
key as input, returning the shared secret along with the ciphertext.

Examples:

```json
"Name": "21_R_P384_SHA384_128",
"Description": "restricted ECC-P384 key using name alg SHA384, with symmetric scheme AES-CFB-128",
"Validated": "TPM2_StartAuthSession",
"Label": "SECRET",
"EphemeralPrivate": "18fc9c02e2512d1cdfb85796edfeeb3e06ea6d122ffd789b2dc1b86e8a1a9dcfe06723274bcf2b32c0fe77cdb616bb99",
"PublicKey": "0023000c000304600030faaa97a96648cf3028b4c29e62587317ed03d3bef5f50958523c21593b020a2fa177964893ca758b26f0a5f16d0d0c1c0006008000430010000400100030f3d876b8b4a75983071628332bf962bb5c00ce2bb5adf84ec78cc09abd3f9e9778b942ad61a70f4e3e6dc8cb2895540e0030da2b5d98eb3fdb93b6f4aebfc03ca06ab4f4bd6c68e313584773e75fe69d32a74c7b7b3fb84f89ab302080b047c8b2b7",
"PrivateKey": "002300300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000030c17c2b320ade7f3f7d3557c23c75197edd169dae126ae7f3eefff93816da29838fe4abf392ca30e08d56e645d11484a700303afbfd2f0c4c85553df47cb020b0b1194e3ceb22392ac15e4b9631b9ba94170f5f3752c345234cbaeb3c5768ddbf5561",
"Secret": "37766b8c172f9e77ae9d6a8660080532f25b8b14c4b5085f0079b8a6e34021c9341421f8be0f8c73032195e99ed4032e",
"Ciphertext": "003094151e6b99a809e982625bc2451ce01061c8383fe55b0eff414c3487d3be166b1f239fc3fedac0ca06eb52d102283392003016e1d63fd3400ec40654af6b9cd7fe826e9e5e4ef937862685fe43953334ead34fcdeab2250903547fdaabd69363c112"
```

```json
"Name": "50_U_P256_SHA256_ECDH_SHA1",
"Description": "unrestricted ECC-P256 key using name alg SHA256, with ECC scheme ECDH using hash alg SHA1",
"Label": "IDENTITY",
"EphemeralPrivate": "7617606d3da7c93f9070b70902b7e6d2ecfde9b83f6e38194fe5fdd8e92ee9c4",
"PublicKey": "0023000b000204600020bef56b8c1cc84e11edd717528d2cd99356bd2bbf8f015209c3f84aeeaba8e8a2001000190004000300100020b882493464101b39fd3b6dcb6448817e66c1800d7e61791499b26b0bb9c923810020ce59ff6dabac71b93bdadb7128aabe8e7d78f27502e41b4cd8cc21673c61145a",
"PrivateKey": "00230020000000000000000000000000000000000000000000000000000000000000000000000020791ab7f8f11bde986740e88aa6d349080fd17f2caf6f9cbb7ccd5ed4927e22cf",
"Secret": "b9e44a52409f11c1ba1ea6b2dce17d1e25382c2d7e0b26a825f250b785dc93df",
"Ciphertext": "0020116d29f71b18ee0442c5dd9625015a1e185a11fc67845b8e603ad984075e340100208f9470e684b59445d2dbc66fe6426af5158f741f38cb29551ef83f34c16720f9"
```

### Name

Type: string

Short name of the test case.

### Description

Type: string

Descriptive name of the test case, including the curve, name hash algorithm,
and scheme or symmetric details (depending on if the key is *restricted*).
This is because only *restricted* *decrypt* keys can have symmetric parameters
set for credential/child object projection, while only non-*restricted*
*decrypt* keys can have a scheme set (i.e., ECDH).

### Validated

Type: string

Optional. Explanation of whether and how this particular test vector was
validated against a TPM simulator.

Not all test cases can be validated against a TPM simulator (e.g., label
"IDENTITY" with a non-*restricted* key).

### Label

Type: string

Label used to differentiate secret-sharing protocols (e.g., for
ActivateCredential, Import, or StartAuthSession). Note that all uses include
the trailing `NUL`.

### EphemeralPrivate

Type: binary (encoded as hex string)

Ephemeral private key (i.e., *d* value) used in one-pass EC Diffie-Hellman.

### PublicKey

Type: binary (encoded as hex string)

Serialized `TPMT_PUBLIC` of the public key.

### PrivateKey

Type: binary (encoded as hex string)

Serialized `TPMT_SENSITIVE` of the private key.

### Secret

Type: binary (encoded as hex string)

Shared secret value.

### Ciphertext

Type: binary (encoded as hex string)

Ciphertext `TPM2BEncryptedSecret` contents.

## rsa_labeled_encaps

RSA Labeled Encapsulation test vectors correspond to RSA Secret Sharing
operations from the TPM 2.0 Specification (Part 1).

Note that RSA Labeled Encapsulation uses the target public key's OAEP scheme
if set (which can only be the case on non-*restricted* *decrypt* keys).

An implementation of "derandomized" RSA Labeled Encapsulation will need to
take the random secret as well as the random OAEP salt, along with the label and
public key as input, returning the ciphertext. (The shared secret is the same
as the random secret that was encrypted using OAEP, so it is not listed twice
in these test vectors).

Examples:

```json
"Name": "14_R_2048_SHA384_128",
"Description": "restricted RSA-2048 key using name alg SHA384, with symmetric scheme AES-CFB-128",
"Validated": "TPM2_ActivateCredential",
"Label": "IDENTITY",
"OAEPSalt": "b98cd78cfafaa12a36a025a0699193787d4572da33eb123e9101b70b69c553d3f857951c77a549f54caf016892bdca00",
"PublicKey": "0001000c000304600030faaa97a96648cf3028b4c29e62587317ed03d3bef5f50958523c21593b020a2fa177964893ca758b26f0a5f16d0d0c1c0006008000430010080000000000010080131aa066c29615ec051a1113f6f36f67089f4cd860950bdcfecc5921bf3491d88ba5c9e92f1f1bd7ffb13f33d67d5025b744f189d933b228e510d25fd71773d0087e6ae861eb07fc82ac521c210727554bcfd67ad5f4b8fe29adf0354650c826c7031155b8731bab9dfb857245bffaea75e10a66b16ac22bd7ffae28be8315a24c136ba7910f46f524f0c30efbf0dadcd0a069f73fe3f2c26bc24af659a5a90b932b2a0c065128c26716ae1fc4e0c3e8b68996c38a7b1193c63dcd71d26e9df725ec387413399fe9903565299959b010b2a51deb48f10c7df21cac2ad99bb562c17e54245ca5a3cb8a8a6e17c525c1a0056f10de1ac8d3734ddc62fdc22f39",
"PrivateKey": "000100300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000030e8029a361201c2c47f901e3e6caba81582acb9e5b435aeec86d215f7a4aa7b7b405fc5c205ec99a064cbb567d7ba71cb0080b51c2d5e49543503e16b3a4d4cd33a34cf16828945b3b88b1fbba3ec46cb565d7d780cd30618f8caeafc360a2635508dba341c55d7acc8cf07feb89d958842fbf49819dc91347423123e287f61cf5f5ffcc1daec126efdeaad80ea0c4280adf3cd0251b7c56887943f5fbae7c0aef1c08b7cf1c438363f9f89e7ebe5974fac4b",
"Secret": "006b21d480be604e53ced19722f7a28768146c13cd1c5acfe2f05337482e39ab38f2643c0ac349367a2175ad2655984a",
"Ciphertext": "27d65cc657239c9706d2d2f665bb8da882f3bd5915f3ec569300a2d5597278e11d40331a55ee65cc72ee627fac9a2d4d9d871ed8f8b6e4ac5ef7812bf87f9c8830b3a92ba8c3ca40e1dd66f7bee57298bfd296c3ca1d668d78a0bd74cea6a566379133a000091d528588777b79d844fbbaada477878556a44b3875c5817597c96ec9baf156496a263bdd1695d45182b1f0240ad114af8907f266a9183be9258ce3bd7f07cc9619afc5db9ccf425ea552cd0ba47f25038ea8ed2820f6906dbc044a53556effcd75961cef9f9d6f43004a776dc5c726192049de678dd99dfbc2ebb47b77c6a15180ee027b4a67eb91722ea6eb9c3356c0721d8cd61b302c6d1562"
```

```json
"Name": "58_U_2048_SHA256_SHA384",
"Description": "unrestricted RSA-2048 key using name alg SHA256, with SHA384 for OAEP",
"Label": "DUPLICATE",
"OAEPSalt": "317df7f9fbf4f6b998e69cc5e9538dc2451874b69f58efe41277abe4e13b9f8b4a1c380bf360a20f1783cb6a6b6813ff",
"PublicKey": "0001000b000204600020bef56b8c1cc84e11edd717528d2cd99356bd2bbf8f015209c3f84aeeaba8e8a200100017000c0800000000000100802e744a3c60f9fb51727c05be87261db4ce7dd6e37a2eeb1c8bcb155e04a4558a8094fd2add0e2139f3612c8c0d8459a46826069b335530215c9dd062e5858e066c544adab44a9a59882d41ca83ee92d04a7ed65e750ec1cd8092cd3519a0f14da1995d441acce3b973cd2e132c981dd7f8ef7686062eb24b43121db13cd69eee860fb70eb1c059c2f5192fa013e847c7da74e77f09162a0836e5ec4d70b0241bef63cd3366df3b78496fe34cf39c43aaa67c33180218765784fd6913f6cd83e0a515da9e401827d672dac451658d0202225517e1082c07f8c2dd94048e0ed2d2ece20a7e9afbd6b2131d39cdacd88c1410b11a3f8e443502c0c48bf96b1e63",
"PrivateKey": "00010020000000000000000000000000000000000000000000000000000000000000000000000080b53e1de1389d8a3984ac9a24ace29c3d68765a0925e9d63a88bb5584814c4a84d2b15ddc7921660b1f727df697e3d9f531258f52f38272e5b5905377aaceb7e1f62eb887e944c739b27fd04ffb888f7f0aeac05da2ce300f0db03183eb76d45c68336639865db0a4b53b7c5e9e2a0b625e6eb2e58b94813e8fd2589fc6b4fed5",
"Secret": "00422b79ddf51ffc977b11bb2e6371a9a7d91d1eb395aeb4d8a43c844bd08a38640c021a8d0ac5dfca7a249a34781948",
"Ciphertext": "2c1ed80cc2257e427b60b1e8217f6705acf307edeb735a0bc0e7f372f7b5af1286e693f3b57d9de2bf6aadd58123d2c22762403306a9383179f0c2bdce85248a255331ebdaa9feb1bd0e26bdf4eb154a414b8ea8af3dae4f7700beb1428fd6c110a38e9abb7bb1126cdd18bbad8b3184b7015e21faf983b52b2e958f3a782fd5669447a21b9d8effb537c53d9cedc94115a777e050c21a47287a41955f6cd71ef50bae319a515101d0b67480f146793d7bd78b8244a72030141924c340d991070279d42a5450e44a8b7fbea1e38139f05c6f89f32f781b223f860e5918e4a0d3c704a9ee57ae77f4f445738afe860b88ab19a01f758f278a4448ce4312ac6e91"
```

### Name

Type: string

Short name of the test case.

### Description

Type: string

Descriptive name of the test case, including the curve, key size, name hash
algorithm, and scheme or symmetric details (depending on if the key is
*restricted*). This is because only *restricted* *decrypt* keys can have
symmetric parameters set for credential/child object projection, while only
non-*restricted* *decrypt* keys can have a scheme set (i.e., OAEP).

### Validated

Type: string

Optional. Explanation of whether and how this particular test vector was
validated against a TPM simulator.

Not all test cases can be validated against a TPM simulator (e.g., label
"IDENTITY" with a non-*restricted* key).

### Label

Type: string

Label used to differentiate secret-sharing protocols (e.g., for
ActivateCredential, Import, or StartAuthSession). Note that all uses include
the trailing `NUL`.

### OAEPSalt

Type: binary (encoded as hex string)

Random salt value used in OAEP encryption.

### PublicKey

Type: binary (encoded as hex string)

Serialized `TPMT_PUBLIC` of the public key.

### PrivateKey

Type: binary (encoded as hex string)

Serialized `TPMT_SENSITIVE` of the private key.

### Secret

Type: binary (encoded as hex string)

Shared secret value.

### Ciphertext

Type: binary (encoded as hex string)

Ciphertext `TPM2BEncryptedSecret` contents.
