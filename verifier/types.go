package verifier

import (
	kyvernov1 "github.com/kyverno/kyverno/api/kyverno/v1"
	imageutils "github.com/kyverno/kyverno/pkg/utils/image"
)

var (
	CertFile = "/certs/tls.crt"
	KeyFile  = "/certs/tls.key"
)

type ImageInfo struct {
	imageutils.ImageInfo

	// Pointer is the path to the image object in the resource
	Pointer string `json:"jsonPointer"`
}

type Type struct {
	// Name is the media type of the attestation
	Name string `json:"type"`

	// Conditions are used to determine if a policy rule should be applied by evaluating a
	// set of conditions. The declaration can contain nested `any` or `all` statements.
	Conditions kyvernov1.AnyAllConditions `json:"conditions"`
}

type AttestationsInfo struct {
	// Image references are the regex of the images containing these attestations
	ImageReference string `json:"imageReference"`

	// type is a list of all the attestation types to check in these images
	Type []Type `json:"type"`
}

type ImageInfos struct {
	// InitContainers is a map of init containers image data from the AdmissionReview request, key is the container name
	InitContainers map[string]ImageInfo `json:"initContainers,omitempty"`

	// Containers is a map of containers image data from the AdmissionReview request, key is the container name
	Containers map[string]ImageInfo `json:"containers,omitempty"`

	// EphemeralContainers is a map of ephemeral containers image data from the AdmissionReview request, key is the container name
	EphemeralContainers map[string]ImageInfo `json:"ephemeralContainers,omitempty"`
}

type Image struct {
	// Name of the container
	Name string `json:"name"`

	// Path to the image object in the resource
	Path string `json:"path"`

	// Updated image with the digest
	Image string `json:"image"`
}

type Attestation struct {
	// Type is the artifact type of the attestation
	Type string `json:"type"`

	// Image the attestation was linked to
	Image string `json:"image"`

	// Payload is the contents of the attestation
	Payload map[string]interface{} `json:"payload"`
}

// Data format of request body for HandleCheckImages
type RequestData struct {
	// List of images in the form of kyverno's image variable
	Images ImageInfos `json:"images"`

	// List of image regex and attestations
	Attestations []AttestationsInfo `json:"attestations"`
}

// Data format of response body for HandleCheckImages
type ResponseData struct {
	// Verified is true when all the images are verified.
	Verified bool `json:"verified"`

	// Message contains an optional custom message to send as a response.
	Message string `json:"message,omitempty"`

	// Images contains the list of containers in JSONPatch format
	Images []Image `json:"results"`

	// Attestations is the list of all the verified attestation
	Attestations []Attestation `json:"attestations"`
}
