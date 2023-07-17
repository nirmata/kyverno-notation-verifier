package verifier

import (
	"encoding/json"

	"github.com/pkg/errors"
)

type Response struct {
	ImageList map[string]AttestationList

	ResponseData ResponseData
}

func NewResponse() *Response {
	imageList := make(map[string]AttestationList)

	responseData := ResponseData{
		Verified:     true,
		Images:       make([]Image, 0),
		Attestations: make([]Attestation, 0),
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

func (r *Response) VerificationFailed(msg string) ([]byte, error) {
	r.ResponseData.Verified = false
	r.ResponseData.Message = msg
	r.ResponseData.Images = nil
	r.ResponseData.Attestations = nil

	data, err := json.MarshalIndent(r.ResponseData, "  ", "  ")
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal response")
	}
	return data, nil
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

func (r *Response) AddAttestations(img string, att string) error {
	if _, found := r.ImageList[img]; found {
		r.ImageList[img][att] = true
	} else {
		return errors.New("Image not found in image list")
	}
	return nil
}

func (r *Response) VerificationSucceeded(msg string) ([]byte, error) {
	r.ResponseData.Message = msg

	data, err := json.MarshalIndent(r.ResponseData, "  ", "  ")
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal response")
	}
	return data, nil
}
