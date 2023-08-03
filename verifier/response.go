package verifier

import (
	"encoding/json"
	"regexp"

	kyvernov1 "github.com/kyverno/kyverno/api/kyverno/v1"
	"github.com/nirmata/kyverno-notation-verifier/types"
	"github.com/pkg/errors"
)

type Response interface {
	GetResponse() types.ResponseData
	GetImageList() map[string]types.AttestationList
	AddImage(img *types.ImageInfo)
	BuildAttestationList(Attestations []types.AttestationsInfo) error
	VerificationFailed(msg string) ([]byte, error)
	VerificationSucceeded(msg string) ([]byte, error)
}

type responseStruct struct {
	imageList map[string]types.AttestationList

	responseData types.ResponseData
}

func NewResponse() Response {
	imageList := make(map[string]types.AttestationList)

	responseData := types.ResponseData{
		Verified: true,
		Results:  make([]types.Result, 0),
	}

	return &responseStruct{
		imageList:    imageList,
		responseData: responseData,
	}
}

func (r *responseStruct) GetResponse() types.ResponseData {
	return r.responseData
}

func (r *responseStruct) GetImageList() map[string]types.AttestationList {
	return r.imageList
}

func (r *responseStruct) AddImage(img *types.ImageInfo) {
	imageData := types.Result{
		Name:  img.Name,
		Path:  img.Pointer,
		Image: img.String(),
	}

	r.responseData.Results = append(r.responseData.Results, imageData)
	r.imageList[img.String()] = make(types.AttestationList)
}

func (r *responseStruct) addAttestations(img string, att types.AttestationType) error {
	if _, found := r.imageList[img]; found {
		if _, ok := r.imageList[img][att.Name]; ok {
			r.imageList[img][att.Name] = append(r.imageList[img][att.Name], att.Conditions)
		} else {
			if len(att.Conditions.AllConditions) != 0 && len(att.Conditions.AnyConditions) != 0 {
				r.imageList[img][att.Name] = make([]kyvernov1.AnyAllConditions, 1)
				r.imageList[img][att.Name][0] = att.Conditions
			} else {
				r.imageList[img][att.Name] = make([]kyvernov1.AnyAllConditions, 0)
			}
		}
	} else {
		return errors.New("Image not found in image list")
	}
	return nil
}

func (r *responseStruct) VerificationFailed(msg string) ([]byte, error) {
	r.responseData.Verified = false
	r.responseData.ErrorMessage = msg
	r.responseData.Results = nil

	data, err := json.MarshalIndent(r.responseData, "  ", "  ")
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal response")
	}
	return data, nil
}

func (r *responseStruct) VerificationSucceeded(msg string) ([]byte, error) {
	r.responseData.ErrorMessage = msg

	data, err := json.MarshalIndent(r.responseData, "  ", "  ")
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal response")
	}
	return data, nil
}

func (r *responseStruct) BuildAttestationList(Attestations []types.AttestationsInfo) error {
	for _, attestation := range Attestations {
		var imagePattern = regexp.MustCompile(attestation.ImageReference)
		for image := range r.imageList {
			if imagePattern.MatchString(image) {
				for _, attestationType := range attestation.Type {
					if err := r.addAttestations(image, attestationType); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}