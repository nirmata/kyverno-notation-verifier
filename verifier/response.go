package verifier

import "errors"

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

func (r *Response) ContinueVerifying() bool {
	return r.GetResponse().Verified
}

func (r *Response) VerificationFailed(msg string) {
	if !r.ContinueVerifying() {
		return
	}

	r.ResponseData.Verified = false
	r.ResponseData.Message = msg
	r.ResponseData.Images = nil
	r.ResponseData.Attestations = nil
}

func (r *Response) AddImage(img *ImageInfo) {
	if !r.ContinueVerifying() {
		return
	}

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
