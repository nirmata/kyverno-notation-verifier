package verifier

import (
	kyvernov1 "github.com/kyverno/kyverno/api/kyverno/v1"
	"github.com/kyverno/kyverno/pkg/utils/wildcard"
	"github.com/nirmata/kyverno-notation-verifier/pkg/types"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"gomodules.xyz/jsonpatch/v2"
)

type Response interface {
	GetResponse() types.ResponseData
	GetImageList() map[string]types.AttestationList
	AddImage(imageRef string, img *types.ImageInfo)
	BuildAttestationList(Attestations []types.AttestationsInfo) error
	VerificationFailed(msg string) (types.ResponseData, error)
	VerificationSucceeded(msg string) (types.ResponseData, error)
}

type responseStruct struct {
	log          *zap.SugaredLogger
	imageList    map[string]types.AttestationList
	responseData types.ResponseData
	ivm          ImageVerifierMetatdata
}

func NewResponse(log *zap.SugaredLogger, ivm ImageVerifierMetatdata) Response {
	imageList := make(map[string]types.AttestationList)

	responseData := types.ResponseData{
		Verified: true,
		Results:  make([]jsonpatch.Operation, 0),
	}

	return &responseStruct{
		log:          log,
		imageList:    imageList,
		responseData: responseData,
		ivm:          ivm,
	}
}

func (r *responseStruct) GetResponse() types.ResponseData {
	return r.responseData
}

func (r *responseStruct) GetImageList() map[string]types.AttestationList {
	return r.imageList
}

func (r *responseStruct) AddImage(imageRef string, img *types.ImageInfo) {
	imageData := jsonpatch.Operation{
		Operation: "replace",
		Path:      img.Pointer,
		Value:     img.String(),
	}

	r.responseData.Results = append(r.responseData.Results, imageData)
	r.imageList[imageRef] = make(types.AttestationList)
}

func (r *responseStruct) addAttestations(img string, att types.AttestationType) error {
	r.log.Infof("Adding attestations %s %v", img, att)
	if _, found := r.imageList[img]; found {
		if _, ok := r.imageList[img][att.Name]; !ok {
			r.imageList[img][att.Name] = make([]kyvernov1.AnyAllConditions, 0)
		}
		if len(att.Conditions.AllConditions) != 0 || len(att.Conditions.AnyConditions) != 0 {
			r.imageList[img][att.Name] = append(r.imageList[img][att.Name], att.Conditions)
		}
	} else {
		return errors.New("Image not found in image list")
	}
	return nil
}

func (r *responseStruct) VerificationFailed(msg string) (types.ResponseData, error) {
	r.log.Errorf("Verification failed with error %s", msg)
	r.responseData.Verified = false
	r.responseData.ErrorMessage = msg
	r.responseData.Results = make([]jsonpatch.Operation, 0)

	return r.responseData, nil
}

func (r *responseStruct) VerificationSucceeded(msg string) (types.ResponseData, error) {
	r.responseData.ErrorMessage = msg

	// TODO: Fix Annotation patching
	// annotationValue, err := json.Marshal(r.ivm.GetAnnotation())
	// if err != nil {
	// 	return r.responseData, err
	// }

	// annotatationPatch := jsonpatch.Operation{
	// 	Operation: r.ivm.GetJSONPatchOperation(),
	// 	Path:      r.ivm.GetAnnotationKeyForJSONPatch(),
	// 	Value:     string(annotationValue),
	// }

	// r.responseData.Results = append(r.responseData.Results, annotatationPatch)

	r.log.Infof("Sending response result=%+v", r.responseData.Results)
	return r.responseData, nil
}

func (r *responseStruct) BuildAttestationList(Attestations []types.AttestationsInfo) error {
	r.log.Infof("building attestation set %v", Attestations)
	for _, attestation := range Attestations {
		for image := range r.imageList {
			if wildcard.Match(attestation.ImageReference, image) {
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
