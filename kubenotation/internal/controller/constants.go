package controller

import "os"

var (
	notationPathEnvVar = "NOTATION_DIR"
	notationPath       = "/tmp/notation"
	trustStorePath     = "truststore/x509"
	finalizerName      = "notation.nirmata.io/finalizer"
)

func init() {
	if os.Getenv(notationPathEnvVar) != "" {
		notationPath = os.Getenv(notationPathEnvVar)
	}
}
