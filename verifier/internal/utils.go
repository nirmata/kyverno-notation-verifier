package internal

import (
	"github.com/nirmata/kyverno-notation-verifier/types"
	"github.com/pkg/errors"
)

func ValidateRequestData(req *types.RequestData) error {
	if len(req.Images.Containers) == 0 &&
		len(req.Images.InitContainers) == 0 &&
		len(req.Images.EphemeralContainers) == 0 {
		return errors.New("atleast one image must be provided")
	}
	for _, att := range req.Attestations {
		if att.ImageReference == "" {
			return errors.Errorf("image reference cannot be empty %+v", att)
		}

		for _, attType := range att.Type {
			if attType.Name == "" {
				return errors.Errorf("attestation name cannot be empty")
			}
			for _, any := range attType.Conditions.AnyConditions {
				if any.RawKey == nil {
					return errors.Errorf("condition key cannot be empty")
				}

				if any.RawValue == nil {
					return errors.Errorf("condition value cannot be empty")
				}
			}

			for _, all := range attType.Conditions.AllConditions {
				if all.RawKey == nil {
					return errors.Errorf("condition key cannot be empty")
				}

				if all.RawValue == nil {
					return errors.Errorf("condition value cannot be empty")
				}
			}
		}
	}
	return nil
}
