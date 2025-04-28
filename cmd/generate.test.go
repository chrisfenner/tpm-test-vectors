// Package main implements the entry logic for the test vector generator
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"

	"github.com/chrisfenner/tpm-test-vectors/pkg/ecckem"
	"github.com/chrisfenner/tpm-test-vectors/pkg/kdfa"
	"github.com/chrisfenner/tpm-test-vectors/pkg/kdfe"
	"github.com/chrisfenner/tpm-test-vectors/pkg/rsakem"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/tcp"
)

var (
	help    = flag.Bool("help", false, "print help")
	tpmCmd  = flag.Int("tpm_cmd_port", 2321, "TCP TPM simulator command port (default 2321)")
	tpmPlat = flag.Int("tpm_plat_port", 2322, "TCP TPM simulator platform port (default 2322)")
	kind    = flag.String("kind", "", "type of test vector to generate")
	count   = flag.Int("count", 1, "number of test vectors to generate")
)

func printUsage() {
	var usage strings.Builder
	fmt.Fprintf(&usage, "Usage:\n")
	fmt.Fprintf(&usage, "  go run cmd/generate.test.go --count <COUNT> --kind <KIND>\n")
	fmt.Fprintf(&usage, "    [ --tpm_cmd_port <PORT> --tpm_plat_port <PORT> ]")
	fmt.Fprintf(&usage, "  where <COUNT> is a positive integer\n")
	fmt.Fprintf(&usage, "  and <KIND> is one of:\n")
	fmt.Fprintf(&usage, "    * kdfa\n")
	fmt.Fprintf(&usage, "    * kdfe\n")
	fmt.Fprintf(&usage, "    * rsa_labeled_encaps\n")
	fmt.Fprintf(&usage, "    * ecc_labeled_encaps\n")
	fmt.Fprintf(&usage, "  and <PORT> the cmd/plat port for a running TPM simulator\n")

	fmt.Printf("%v\n", usage.String())
}

func main() {
	flag.Parse()
	if *help {
		printUsage()
		return
	}

	if err := mainErr(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func mainErr() error {
	if *count < 1 {
		return errors.New("--count must be a positive integer")
	}
	tpm, err := getTPM(*tpmCmd, *tpmPlat)
	if err != nil {
		return err
	}
	defer tpm.Close()
	vectors, err := generateTestVectors(tpm, *kind, *count)
	if err != nil {
		return err
	}
	json, err := json.MarshalIndent(vectors, "", "    ")
	if err != nil {
		return err
	}
	fmt.Printf("%v\n", string(json))
	return nil
}

// getTPM opens a connection to the TPM and starts it up if needed.
func getTPM(tpmCmd int, tpmPlat int) (transport.TPMCloser, error) {
	tpm, err := tcp.Open(tcp.Config{
		CommandAddress:  fmt.Sprintf("localhost:%d", tpmCmd),
		PlatformAddress: fmt.Sprintf("localhost:%d", tpmPlat),
	})
	if err != nil {
		return nil, err
	}
	if err := tpm.PowerOn(); err != nil {
		return nil, err
	}
	_, err = tpm2.Startup{
		StartupType: tpm2.TPMSUClear,
	}.Execute(tpm)
	if err != nil && !errors.Is(err, tpm2.TPMRCInitialize) {
		return nil, fmt.Errorf("unexpected error from Startup(): %w", err)
	}
	return tpm, nil
}

type testVector interface {
	VectorName() string
	SetName(name string)
}

// generateTestVectors generates the requested test vectors, validating them using the TPM first if possible.
func generateTestVectors(tpm transport.TPM, kind string, count int) ([]testVector, error) {
	result := make([]testVector, count)
	var err error
	for i := range result {
		var testVector testVector
		switch strings.ToLower(kind) {
		case "kdfa":
			testVector, err = kdfa.GenerateTestVector(tpm)
			if err != nil {
				return nil, err
			}
		case "kdfe":
			testVector, err = kdfe.GenerateTestVector(tpm)
			if err != nil {
				return nil, err
			}
		case "rsa_labeled_encaps":
			testVector, err = rsakem.GenerateTestVector(tpm)
			if err != nil {
				return nil, err
			}
		case "ecc_labeled_encaps":
			testVector, err = ecckem.GenerateTestVector(tpm)
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unrecognized --kind value, expected one of {kdfa, kdfe, labeled_encaps}, was %q", kind)
		}
		result[i] = testVector
	}

	sort.Slice(result, func(a, b int) bool {
		return strings.Compare(result[a].VectorName(), result[b].VectorName()) < 0
	})

	formatDigits := int(math.Ceil(math.Log10(float64(count))))
	formatString := fmt.Sprintf("%%0%dd_%%s", formatDigits)

	for i := range result {
		result[i].SetName(fmt.Sprintf(formatString, i, result[i].VectorName()))
	}

	return result, nil
}
