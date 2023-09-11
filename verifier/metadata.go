package verifier

import (
	"strings"
)

type imageVerifierMetatdata struct {
	annotation map[string]bool
}

type ImageVerifierMetatdata interface {
	Add(image string, value bool)
	GetAnnotation() map[string]bool
	IsVerified(image string) bool
}

func NewImageVerifierMetatdata(annotation map[string]bool) ImageVerifierMetatdata {
	if len(annotation) == 0 {
		annotation = make(map[string]bool)
	}

	return &imageVerifierMetatdata{
		annotation: annotation,
	}
}

func (ivm *imageVerifierMetatdata) Add(image string, value bool) {
	if val, found := ivm.annotation[image]; !found || !val {
		ivm.annotation[image] = value
	}
}

func (ivm *imageVerifierMetatdata) GetAnnotation() map[string]bool {
	return ivm.annotation
}

func (ivm *imageVerifierMetatdata) IsVerified(image string) bool {
	if ivm.annotation == nil {
		return false
	}
	verified, ok := ivm.annotation[image]
	if !ok {
		return false
	}
	return verified
}

func makeAnnotationKeyForJSONPatch() string {
	return "/metadata/annotations/" + strings.ReplaceAll("kyverno-notation-aws.io/verify-images", "/", "~1")
}
