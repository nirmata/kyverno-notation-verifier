package verifier

import (
	"github.com/nirmata/kyverno-notation-verifier/types"
	"github.com/pkg/errors"
)

func validateRequestData(req *types.RequestData) error {
	if len(req.Images.Containers) == 0 &&
		len(req.Images.InitContainers) == 0 &&
		len(req.Images.EphemeralContainers) == 0 {
		return errors.New("atleast one image must be provided")
	}

	return nil
}
