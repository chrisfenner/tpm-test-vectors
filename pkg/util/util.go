// Package util implements helpers for generating data in test vectors.
package util

func FormatLabel(label string) []byte {
	result := make([]byte, len(label)+1)
	copy(result, []byte(label))
	return result
}
