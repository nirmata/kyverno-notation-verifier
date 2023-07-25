package verifier

import (
	"net/http"

	"github.com/cenkalti/backoff/v4"
	"go.uber.org/zap"
)

type Verifier interface {
	// HandleCheckImages is a handler function that takes Kyverno images variable in body and returns JSONPatch compatible object in response
	HandleCheckImages(w http.ResponseWriter, r *http.Request)

	UpdateNotationVerfier() error
	// Shuts down all the factories before exiting
	Stop()
}

func NewVerifier(logger *zap.SugaredLogger, opts ...verifierOptsFunc) Verifier {
	var verifier *verifier
	var err error

	initVerifier := func() error {
		verifier, err = newVerifier(logger, opts...)
		return err
	}

	if err := backoff.Retry(initVerifier, backoff.NewExponentialBackOff()); err != nil {
		logger.Fatalf("initialization failed, retrying, error: %v", err)
	}

	return verifier
}
