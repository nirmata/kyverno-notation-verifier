package types

import (
	imageutils "github.com/kyverno/kyverno/pkg/utils/image"
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

type ImageInfos struct {
	// InitContainers is a map of init containers image data from the AdmissionReview request, key is the container name
	InitContainers map[string]ImageInfo `json:"initContainers,omitempty"`

	// Containers is a map of containers image data from the AdmissionReview request, key is the container name
	Containers map[string]ImageInfo `json:"containers,omitempty"`

	// EphemeralContainers is a map of ephemeral containers image data from the AdmissionReview request, key is the container name
	EphemeralContainers map[string]ImageInfo `json:"ephemeralContainers,omitempty"`
}

type Result struct {
	// Name of the container
	Name string `json:"name"`

	// Path to the image object in the resource
	Path string `json:"path"`

	// Updated image with the digest
	Image string `json:"image"`
}

// Data format of request body for HandleCheckImages
type RequestData struct {
	Images ImageInfos `json:"images"`

	TrustPolicy string `json:"trustPolicy"`
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
	Results []Result `json:"results"`
}
