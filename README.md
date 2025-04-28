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

Descriptive name of the test case, including the hash algorithm and bits of
output.

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

Descriptive name of the test case, including the hash algorithm and bits of
output.

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

Note that ECC Labeled Encapsulation ignores the target key's ECDH scheme
parameters and always uses *nameAlg* of the target public key.

An implementation of "derandomized" ECC Labeled Encapsulation will need to take
the random ephemeral ECDH private key (*d*) along with the label and public
key as input, returning the shared secret along with the ciphertext.

Examples:

```json
"Name": "10_P256_SHA256_256_restricted",
"Validated": "TPM2_Import",
"Label": "DUPLICATE",
"EphemeralPrivate": "5b10b02cd43d9c8a04b574f4eb19fcdcce516dc9b137a7555810f37a1c4e5c81",
"PublicKey": "0023000b0003046000000006010000430010000300100020fe4cf1f3e8f583c19e1af6190a7c20751658914a93cd77efb871cb1557377560002007b6b7c55bea1d17b1a9d96f367cf315b2942d517fd8642e9d9157036831c4d5",
"Secret": "5b5a13f86045e809c21bf6524d61287799287d4277353ee1a4d8e71cae4d12ca",
"Ciphertext": "00205e16fd0c2688608f0b868b70986266b37e284a253a6252aa4ca4a077d2daf9d80020b29ecaa9691309c5b251c55f3b54e32c5d81f01b999227ccf54ba07a532188a8"
```

```json
"Name": "17_P256_SHA256_SHA1_unrestricted",
"Validated": "TPM2_StartAuthSession",
"Label": "SECRET",
"EphemeralPrivate": "05ab558b85bf953e76d16fd29ec19ee0f99d67767e0536c6a5d3c153ac1fe52d",
"PublicKey": "0023000b0002046000000010001900040003001000201104221d8bfa95cd029b1ec7187112f643a5eec449fb17d0e93f533228a6a60a002074441cc6a418de9e6a382a8722024f7b2d343c602c92a338b02d82794530fbf6",
"Secret": "96c83694c408fd4847f9e404f0b93357c81fbc48b86816ffc7c6d907e77def08",
"Ciphertext": "002015b1b494f4d56e91e372c3c49d69875ab442d71fe068459817e431c908e4421100200949e79572cdc5ccdd7b823c682d5174acc1a566b3be764cc9e78a92b5d56c2c"
```

### Name

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
"Name": "09_2048_SHA256_128_restricted",
"Validated": "TPM2_Import",
"Label": "DUPLICATE",
"OAEPSalt": "45f3b20066316295a445d670aee039cac8a765c4e683ba948d51110aad0bb9ff",
"PublicKey": "0001000b000304600000000600800043001008000000000001008054bc2c75a670a0d6372d5d37944609a79e94865c48c16c46e9354912f4aab3213c2cb204f104329de5a6e21fd459ad7e5e6e9afbbd8ee14d22ebd23821815be7b3e225ffd06c0097b91b0e0d71c27d5eee235ea37ae1d6ff84ffca71ea9926103ab5da58befeaad5df0de20662cc05096706aeafaaa5b231e6bd0fddbb26c1fa1c9f05861e11525360373789f9e07c96d65f8a9f3483bb7d95e5286ed66b4ae5588e5ed38ab15d40059b5c7d8d9ef0a67d7ab9e0b923f618e5a2cddad5b644080391196d0214d6d4bef749cb8228b947ea0a1feb305414e0023ec6022e1b8098f96a53c1e878ddb85a3dc39dbbfc600bffaa34ace17465825ddccd7796dbaf",
"Secret": "f2967d61ba8a08c9f1877f1965868ded9e418057b984b17fcc40f55e00035b00",
"Ciphertext": "116936814cee006c2acbe000cebdc22afd7a2f5ede9d05b0e88900a2a98cdd09c4841f31e7ffa337d22f6e69b530929a440082d9e4e880dd00b7630d989f71ac7ac220c2f9bab31950eba8b77cf5e4813223eefe4b5b1b5e952888e3dcddd101320c17d77106c67251e42ca888d585085c3ec43b0ef6c6aeeb63057d3e345d9f35865ba199e740d4724766f9a2be23f684a9c6f1e3236969f0e1cc58250cd9774656dbec546340245d6501e4267e194565847f4dc7f2cea86719abfc85b309f3fb1587b089c9d3c7fc928e1bfafe464803bf19424765e04185220f99e1ed004a8dae0d2798a946a10886247523d455692fdcf7fcce3f198db30d899e160f0d8b"
```

```json
"Name": "18_2048_SHA256_SHA384_unrestricted",
"Validated": "TPM2_StartAuthSession",
"Label": "SECRET",
"OAEPSalt": "ffe8d6fadcc1bc8979aaf105e7f1493a0a026a6426073875a2e64090130e2d65503e023ba9b064b4e9d5afbbaa02fddd",
"PublicKey": "0001000b00020460000000100017000c0800000000000100803359f5826dbd52f706320185dcb9e4ca001f64ad5fb878fe79731218ca8a08d4b0c60cd12f445d75cd8c8ab94b5495ddebfa6c3f0c22c6725ebdf153b7590c0044a0c75624e74132ae45d21edbad80e9624b26bbe4ae7f5c97489e6ad03e08c2da0358c8bd6e8b6e53ffaa926ae0a79abef1a40b4d13f24aac99bf6149feba55972d9e48ee2acbb84f528e2d70e2ce02650e7f8de1b6a5021a99f99b5946e16f97b28b12c203cdc9990d7c7db595ff613cc85613be8e3be04fce0747fd9e605f93a2d1d8482d2eb35c356d960146e828fff81acc5d5160f9fbb7fdfecf2fbdda7ffd3246425046ce1840171b15af8aa307547ac1cbfdbb92cb5e6ffd2f4765",
"Secret": "b8b4c5e5f26f7b2871f6b3357853341c38b641b4308763569ffbc542df2b8af1545eeaf1f57bcd8a23d8a6433ef2a7ff",
"Ciphertext": "5ba50058bc4a003852be19b890ca6f1480ef177b7eb24cd65661e00cb36479bf04e1f427a2584fed22bb3b7390bec70a2aaa5a706b138d2c8a0bd630317f883db923456293d6da4da1aab1427bdcb17af50634c3f8d1b35bb078d16575b32975fce8e6b15e76934911d986209cb410c404200d1bb9efcbed2e701a44ae344404e691c599847d715a015877ad487290131cae943b4ce0268c44bc5f8716dca3e65bc4f50029fe38a2687492422a43ec595efd19b9a90e4488192175819f7f1539a4ae5666dae24d536958f8f26ea9ebf423a8263787f2858460ad06d85d1fb3c79de4bad7a4cc7ba6f139d129d1cbceb03f1f00cf84023147d60a3d1703f51b94"
```

### Name

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

### Secret

Type: binary (encoded as hex string)

Shared secret value.

### Ciphertext

Type: binary (encoded as hex string)

Ciphertext `TPM2BEncryptedSecret` contents.
