package verifier

import "github.com/pkg/errors"

func validateRequestData(req *RequestData) error {
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
				return errors.Errorf("attestation name cannot be empty %+v: %+v", attType, att)
			}
			for _, any := range attType.Conditions.AnyConditions {
				if any.RawKey == nil {
					return errors.Errorf("condtion key cannot be empty %+v: %+v: %+v", any, attType, att)
				}

				if any.RawValue == nil {
					return errors.Errorf("condtion value cannot be empty %+v: %+v: %+v", any, attType, att)
				}
			}

			for _, all := range attType.Conditions.AllConditions {
				if all.RawKey == nil {
					return errors.Errorf("condtion key cannot be empty %+v: %+v: %+v", all, attType, att)
				}

				if all.RawValue == nil {
					return errors.Errorf("condtion value cannot be empty %+v: %+v: %+v", all, attType, att)
				}
			}
		}
	}
	return nil
}
