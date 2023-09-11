package types

import (
	kyvernov1 "github.com/kyverno/kyverno/api/kyverno/v1"
	imageutils "github.com/kyverno/kyverno/pkg/utils/image"
	"gomodules.xyz/jsonpatch/v2"
)

var (
	CertFile                 = "/certs/tls.crt"
	KeyFile                  = "/certs/tls.key"
	ENV_DEFAULT_TRUST_POLICY = "DEFAULT_TRUST_POLICY"
)

type ImageInfo struct {
	imageutils.ImageInfo

	// Pointer is the path to the image object in the resource
	Pointer string `json:"jsonPointer"`
}

type AttestationType struct {
	// Name is the media type of the attestation
	Name string `json:"name"`

	// Conditions are used to determine if a policy rule should be applied by evaluating a
	// set of conditions. The declaration can contain nested `any` or `all` statements.
	Conditions kyvernov1.AnyAllConditions `json:"conditions"`
}

type AttestationsInfo struct {
	// Image references are the regex of the images containing these attestations
	ImageReference string `json:"imageReference"`

	// type is a list of all the attestation types to check in these images
	Type []AttestationType `json:"type"`
}

type ImageInfos struct {
	// InitContainers is a map of init containers image data from the AdmissionReview request, key is the container name
	InitContainers map[string]ImageInfo `json:"initContainers,omitempty"`

	// Containers is a map of containers image data from the AdmissionReview request, key is the container name
	Containers map[string]ImageInfo `json:"containers,omitempty"`

	// EphemeralContainers is a map of ephemeral containers image data from the AdmissionReview request, key is the container name
	EphemeralContainers map[string]ImageInfo `json:"ephemeralContainers,omitempty"`
}

// Data format of request body for HandleCheckImages
type RequestData struct {
	// List of images in the form of kyverno's image variable
	Images ImageInfos `json:"images"`

	// TrustPolicy specifies the name of the trust policy to be used for this specific request
	TrustPolicy string `json:"trustPolicy"`

	// List of image regex and attestations
	Attestations []AttestationsInfo `json:"attestations"`

	// Metadata is the current value of kyverno-notation-aws.io/verify-images annotation
	Metadata string `json:"metadata"`
}

// VerificationRequest is the data sent to verifier after processed from HandleCheckImages request
type VerificationRequest struct {
	// List of images in the form of kyverno's image variable
	Images ImageInfos `json:"images"`

	// TrustPolicy specifies the name of the trust policy to be used for this specific request
	TrustPolicy string `json:"trustPolicy"`

	// List of image regex and attestations
	Attestations []AttestationsInfo `json:"attestations"`

	// Metadata is the current value of kyverno-notation-aws.io/verify-images annotation
	Metadata map[string]bool `json:"metadata"`
}

// Data format of response body for HandleCheckImages
type ResponseData struct {
	// Verified is true when all the images are verified.
	Verified bool `json:"verified"`

	// ErrorMessage contains the error recieved when verification fails
	// ErrorMessage is empty when verification succeeds
	ErrorMessage string `json:"message,omitempty"`

	// Results contains the list of containers in JSONPatch format
	// Results is empty when verification fails
	Results []jsonpatch.JsonPatchOperation `json:"results"`
}

type AttestationList map[string][]kyvernov1.AnyAllConditions
