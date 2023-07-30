package notationfactory

import (
	"github.com/nirmata/kyverno-notation-verifier/types"
	"github.com/notaryproject/notation-go"
)

type NotationVeriferFactory interface {
	// RefreshVerifiers will remove all the existing verifiers and create new ones using the trust policies in notation directory
	RefreshVerifiers() error

	// GetVerifier returns a verifier based on the trust policy in request or the default trustpolicy in trust policy env
	GetVerifier(requestData *types.RequestData) (*notation.Verifier, error)
}
