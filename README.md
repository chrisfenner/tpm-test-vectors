# tpm-test-vectors
Test vector generator for TPM crypto.

# Status of this project

Current status: WIP

Creating a new suite of test vectors for an existing cryptographic protocol
should be done carefully. Proposed test vectors need to be validated against
at least one (ideally multiple) existing known-good implementations of the
protocol. Existing implementations do not always have the necessary hooks for
testing.

This generator is based on [go-tpm](https://github.com/google/go-tpm), which
contains a fairly mature crypto protocol implementation (at least for KDFa and
KDFe).

## Usage

The test vector generation tool uses a running TPM simulator to help validate
its outputs.

```sh
	go run cmd/generate.go --count ${COUNT} --kind ${KIND} --tpm_cmd_port ${PORT} --tpm_plat_port ${PORT}
```

* `$COUNT` is a positive integer, the number of test vectors to generate
* `$KIND` selects the test vector type, and is one of:
  * kdfa
  * kdfe
  * rsa_labeled_encaps
* `$PORT` is the cmd/plat port for a running TPM simulator (default 2321/2322)

## Output

The output is a test-vector-type dependent JSON blob containing the test data. Binary data is encoded in base64.
