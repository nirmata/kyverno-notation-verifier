package verifier

import (
	"encoding/json"
	"regexp"

	kyvernov1 "github.com/kyverno/kyverno/api/kyverno/v1"
	"github.com/pkg/errors"
)

type Response struct {
	ImageList map[string]AttestationList

	ResponseData ResponseData
}

func NewResponse() *Response {
	imageList := make(map[string]AttestationList)

	responseData := ResponseData{
		Verified: true,
		Images:   make([]Image, 0),
	}

	return &Response{
		ImageList:    imageList,
		ResponseData: responseData,
	}
}

func (r *Response) GetResponse() ResponseData {
	return r.ResponseData
}

func (r *Response) GetImageList() map[string]AttestationList {
	return r.ImageList
}

func (r *Response) AddImage(img *ImageInfo) {
	imageData := Image{
		Name:  img.Name,
		Path:  img.Pointer,
		Image: img.String(),
	}

	r.ResponseData.Images = append(r.ResponseData.Images, imageData)
	r.ImageList[img.String()] = make(AttestationList)
}

func (r *Response) AddAttestations(img string, att AttestationType) error {
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
	r.ResponseData.Images = nil

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

func (r *Response) BuildAttestationList(Attestations []AttestationsInfo) error {
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
