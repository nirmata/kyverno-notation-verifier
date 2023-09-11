package verifier

import (
	"strings"
)

type imageVerifierMetatdata struct {
	annotation    map[string]bool
	initialLength int
}

type ImageVerifierMetatdata interface {
	Add(image string, value bool)
	GetAnnotation() map[string]bool
	IsVerified(image string) bool
	GetOperation() string
	GetAnnotationKeyForJSONPatch() string
}

func NewImageVerifierMetatdata(annotation map[string]bool) ImageVerifierMetatdata {
	if len(annotation) == 0 {
		annotation = make(map[string]bool)
	}

	return &imageVerifierMetatdata{
		annotation:    annotation,
		initialLength: len(annotation),
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

func (ivm *imageVerifierMetatdata) GetOperation() string {
	if ivm.initialLength == 0 {
		return "add"
	} else {
		return "replace"
	}
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

func (ivm *imageVerifierMetatdata) GetAnnotationKeyForJSONPatch() string {
	return "/metadata/annotations/" + strings.ReplaceAll("kyverno-notation-aws.io/verify-images", "/", "~1")
}
