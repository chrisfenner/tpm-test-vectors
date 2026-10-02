module github.com/chrisfenner/tpm-test-vectors

go 1.25.0

require github.com/google/go-tpm v0.9.3

require (
	github.com/cloudflare/circl v1.6.5 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

replace github.com/google/go-tpm v0.9.3 => github.com/chrisfenner/go-tpm v0.0.0-20250428201806-3c9c77aaa985
