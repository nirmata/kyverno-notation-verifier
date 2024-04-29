package internal

import (
	"encoding/json"
	"fmt"

	"github.com/nirmata/kyverno-notation-verifier/pkg/types"
	"github.com/pkg/errors"
)

func ProcessRequestData(req *types.RequestData) (*types.VerificationRequest, error) {
	if len(req.Images.Containers) == 0 &&
		len(req.Images.InitContainers) == 0 &&
		len(req.Images.EphemeralContainers) == 0 {
		return nil, errors.New("atleast one image must be provided")
	}
	for _, att := range req.Attestations {
		if att.ImageReference == "" {
			return nil, errors.Errorf("image reference cannot be empty %+v", att)
		}

		for _, attType := range att.Type {
			if attType.Name == "" {
				return nil, errors.Errorf("attestation name cannot be empty")
			}
			for _, any := range attType.Conditions.AnyConditions {
				if any.RawKey == nil {
					return nil, errors.Errorf("condition key cannot be empty")
				}

				if any.RawValue == nil {
					return nil, errors.Errorf("condition value cannot be empty")
				}
			}

			for _, all := range attType.Conditions.AllConditions {
				if all.RawKey == nil {
					return nil, errors.Errorf("condition key cannot be empty")
				}

				if all.RawValue == nil {
					return nil, errors.Errorf("condition value cannot be empty")
				}
			}
		}
	}
	metadata := make(map[string]bool)
	if len(req.Metadata) > 0 {
		if err := json.Unmarshal([]byte(req.Metadata), &metadata); err != nil {
			return nil, fmt.Errorf("failed to marshal metadata value: %w", err)
		}
	}

	return &types.VerificationRequest{
		ImageReferences: req.ImageReferences,
		Images:          req.Images,
		Attestations:    req.Attestations,
		TrustPolicy:     req.TrustPolicy,
		Metadata:        metadata,
	}, nil
}
