package notationfactory

import (
	"github.com/nirmata/kyverno-notation-verifier/types"
	"github.com/notaryproject/notation-go"
)

type NotationVeriferFactory interface {
	// RefreshVerifiers will remove all the existing verifiers and create new ones using the trust policies in notation directory
	RefreshVerifiers() error

	// GetVerifier returns a verifier based on the trust store in request or the default truststore in trust store env
	GetVerifier(requestData *types.RequestData) (*notation.Verifier, error)
}
