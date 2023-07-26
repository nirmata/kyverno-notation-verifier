package utils

import "os"

var (
	NotationPathEnvVar = "NOTATION_DIR"
	NotationPath       = "/tmp/notation"
	TrustStorePath     = "truststore/x509"
	FinalizerName      = "notation.nirmata.io/finalizer"
)

func init() {
	if os.Getenv(NotationPathEnvVar) != "" {
		NotationPath = os.Getenv(NotationPathEnvVar)
	}
}
