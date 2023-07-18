package verifier

import "github.com/pkg/errors"

func validateRequestData(req *RequestData) error {
	if len(req.Images.Containers) == 0 &&
		len(req.Images.InitContainers) == 0 &&
		len(req.Images.EphemeralContainers) == 0 {
		return errors.New("atleast one image must be provided")
	}

	return nil
}
