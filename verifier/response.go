package verifier

import (
	"encoding/json"
	"regexp"

	kyvernov1 "github.com/kyverno/kyverno/api/kyverno/v1"
	"github.com/nirmata/kyverno-notation-verifier/types"
	"github.com/pkg/errors"
)

type Response struct {
	ImageList map[string]types.AttestationList

	ResponseData types.ResponseData
}

func NewResponse() *Response {
	imageList := make(map[string]types.AttestationList)

	responseData := types.ResponseData{
		Verified: true,
		Results:  make([]types.Result, 0),
	}

	return &Response{
		ImageList:    imageList,
		ResponseData: responseData,
	}
}

func (r *Response) GetResponse() types.ResponseData {
	return r.ResponseData
}

func (r *Response) GetImageList() map[string]types.AttestationList {
	return r.ImageList
}

func (r *Response) AddImage(img *types.ImageInfo) {
	imageData := types.Result{
		Name:  img.Name,
		Path:  img.Pointer,
		Image: img.String(),
	}

	r.ResponseData.Results = append(r.ResponseData.Results, imageData)
	r.ImageList[img.String()] = make(types.AttestationList)
}

func (r *Response) AddAttestations(img string, att types.AttestationType) error {
	if _, found := r.ImageList[img]; found {
		if _, ok := r.ImageList[img][att.Name]; ok {
			r.ImageList[img][att.Name] = append(r.ImageList[img][att.Name], att.Conditions)
		} else {
			r.ImageList[img][att.Name] = make([]kyvernov1.AnyAllConditions, 1)
			r.ImageList[img][att.Name][0] = att.Conditions
		}
	} else {
		return errors.New("Image not found in image list")
	}
	return nil
}

func (r *Response) VerificationFailed(msg string) ([]byte, error) {
	r.ResponseData.Verified = false
	r.ResponseData.ErrorMessage = msg
	r.ResponseData.Results = nil

	data, err := json.MarshalIndent(r.ResponseData, "  ", "  ")
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal response")
	}
	return data, nil
}

func (r *Response) VerificationSucceeded(msg string) ([]byte, error) {
	r.ResponseData.ErrorMessage = msg

	data, err := json.MarshalIndent(r.ResponseData, "  ", "  ")
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal response")
	}
	return data, nil
}

func (r *Response) BuildAttestationList(Attestations []types.AttestationsInfo) error {
	for _, attestation := range Attestations {
		var imagePattern = regexp.MustCompile(attestation.ImageReference)
		for image := range r.ImageList {
			if imagePattern.MatchString(image) {
				for _, attestationType := range attestation.Type {
					if err := r.AddAttestations(image, attestationType); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}
