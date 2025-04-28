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
"Name": "08_R_P256_SHA256_128",
"Description": "restricted ECC-P256 key using name alg SHA256, with symmetric scheme AES-CFB-128",
"Validated": "TPM2_ActivateCredential",
"Label": "IDENTITY",
"EphemeralPrivate": "6124ee9ee8b4727619558d19dbb80292fd4381aa51a40b1d264cdef4317b6ffa",
"PublicKey": "0023000b00030460000000060080004300100003001000209cb3efad1473a317e0cfc99c48ccfd30769885ce8824b2679374aa8ef2415cb400203c8797c503170365efd4904b73e42c94a5ca23ae1ea7a352201e36abb47bc04b",
"Secret": "e1f5d7dde52ddc61b4dd28e6489d643183c8857411b0de2a271d0822c0e21852",
"Ciphertext": "0020518aea5837a2547ae439f2e571bf934d2f2caaeca715c415008215e7d058fc6f002099ed18644411548c82e042ea68eb6e9be592325b6a4cff47b5f1cf7dc337ac01"
```

```json
"Name": "57_U_P256_SHA256_ECMQV_SHA1",
"Description": "unrestricted ECC-P256 key using name alg SHA256, with ECC scheme ECMQV using hash alg SHA1",
"Label": "DUPLICATE",
"EphemeralPrivate": "d151c908974bebe739808fdd6f1a785a7940169cec1e0a8b0f211eb4ed714e3e",
"PublicKey": "0023000b0002046000000010001d0004000300100020346f9b719b0d597feb04b8de2379d72039b00a44ba05c357a01202a721dd0faf0020a84dc53b7df3e2339a422f27ad527f704ee874aa3a5e01be8612993bdf60ab08",
"Secret": "5da0c3627bb130d03760dae055d012c0786fcfa9b910f8410fb2064a4425ccec",
"Ciphertext": "0020e9e484d2001008b1aca0c5ccd8c445f900e9326a64439a90a3bdd44e5cf2ccdd0020e125bb94c0b230aa925a51b075d1f64e6934465780da7c96ac1c3c7ea71e2365"
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
"Name": "08_R_2048_SHA256_128",
"Description": "restricted RSA-2048 key using name alg SHA256, with symmetric scheme AES-CFB-128",
"Validated": "TPM2_StartAuthSession",
"Label": "SECRET",
"OAEPSalt": "00944ba581fd9047559a45aad81bb589ef55f8f67a563a05bb0c63a5ef64330c",
"PublicKey": "0001000b00030460000000060080004300100800000000000100801a7b4258c5fb7f4efb049ed5a1344194b476f9c3e348644d3d1eae9a1496c020640f900b905c25afd5aa7d33eba9778b289f9bd5a07e80e824d27b23b07e20b88a7e8c6d0a40be032a6e7560a629aec083b867fd7a579f84eed757540a04985eb0ff314563ffea7540050ccb856c2237cb2baf569afb2b8ae890c3fda844dd778dd51705457a41f643cbc175b29dcea072aba5ad98f06d04c02f2dfd9771fd11b9e0bfe60cd746c0f2a9d691aa5e1278580c5b2adc6c8f99a50e910ef387cd0ed494ae37ebcc75051cd20670596758b3d954a464748622b58fe56932f3dfa8ef8afd00ad5784bf50760bd457255e124491d9c069ab15b876f3b199a39be505",
"Secret": "33d5582e002e689e7ecda6c53856dddde8bfde2c76c6f644f40ced8706995e00",
"Ciphertext": "2659f109f05b8afcd25e10db8b8682ab81b88b8f371fb41bf3a185076fba827764f57a70705325bb7f3672984b70c6a9cd1ecda8904ee351c85b2123e8543796bda2288568903cb291b0ab222f1aa3180f1bd26e30ac675b72a5030067b1827c52ca368f10da9c702c6bacd7361cac642c41e25ad604d51b070602a6c5348299647a8b0fc667833df9649e36e86867af5d0a3de683cd19fc9fe14d382a44855f315c41b9656061399ed0f9cb1a769310a07f8dc7690d71e56d114cce70ee42feb7bbd63cb80443235d72964abc6b0dd44be93f044d2119d207d3959a70bf25e441c031c05d1dd2566dcb552c10c151391476589f4492e789dce60bdd4f5b4705"
```

```json
"Name": "51_U_2048_SHA256_SHA1",
"Description": "unrestricted RSA-2048 key using name alg SHA256, with SHA1 for OAEP",
"Validated": "TPM2_StartAuthSession",
"Label": "SECRET",
"OAEPSalt": "d6094bed070b73fedf6ee07fd8f5087737c065ff",
"PublicKey": "0001000b000204600000001000170004080000000000010080275e48fbdc385f67e8b529a07015ea92ab589e21575c6d9efcd9302d3faf68bb8f5ef932928926ab2aa2fd34d6ff8584cc8db1f6f86415867250972370f46e8647bd69f491f4d9c3a82ee4f871729a23bde61f532a0e60f974e53ec7454852ce485123dc41227d35316e5d1da1381e978ae4c69f62ef2f208fe87f91d4df424c65d966eb3e0f05583e1c33d20f1421ec2253d439f31254d856207a92a641a62f3b80e6c9dccf70ae9383bda580dd08136bd26f49cbb3ca787818c6d7b01ff817817c2054ef61e555bd71c418185fc7b4c91a042e812f2ab3eb0fccf99c4c62520cb5ca0ed4864a2e9246c1338a98487bd591a0686d478f06aabcfb898ceb45",
"Secret": "ff0ac6b2027bde8fdc83fe846fc93c8157e1ab18",
"Ciphertext": "75145c4face1d00e8268a500189d93d75f1b07e90098695720e9ae74943c2a0e405fbe0a2e3414bb08f08b4a0958d36a4886d8b36a87b698ff16740f4981caf27880e1037da4ee3c047571dc532b7c6863e46c38d14286ea054e36ffcb0d6f2a46f171b979d7d6ffb8c6ff2ae83d826cf47b150e8d4023e229037b8d6d1662a178aadcf5b234338c6ce8b2fdee9a210b14bf34490d18587f8af50c9ce09a1bd116ec4e1777446ad32840c9a646e8cacdd6e9769363cc57967fdfc6d1d4511ca39a7aac3eb67742991d2eb9e94e6a4b91ee689a28e1580010a04e0603c597841318cf67dd9ed2d999eee016f620c72873fe7bf2269cb0d18f9104069dc4cefb21"
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

### Secret

Type: binary (encoded as hex string)

Shared secret value.

### Ciphertext

Type: binary (encoded as hex string)

Ciphertext `TPM2BEncryptedSecret` contents.
