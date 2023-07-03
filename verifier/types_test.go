package verifier

import (
	"encoding/json"
	"testing"

	"gotest.tools/assert"
)

var (
	requestBody = `
{
  "images": {
    "containers": {
      "tomcat": {
        "registry": "https://ghcr.io",
        "path": "tomcat",
        "name": "tomcat",
        "tag": "9",
        "jsonPointer": "spec/container/0/image"
      }
    },
    "initContainers": {
      "vault": {
        "registry": "https://ghcr.io",
        "path": "vault",
        "name": "vault",
        "tag": "v3",
        "jsonPointer": "spec/initContainer/0/image"
      }
    }
  },
  "attestations": [
    {
      "imageReference": "*",
      "type": [
        "sbom/cyclone-dx",
        "application/sarif+json"
      ]
    },
    {
      "imageReference": "844333597536.dkr.ecr.us-west-2.amazonaws.com/kyverno-demo:*",
      "type": [
        "application/vnd.cyclonedx"
      ]
    }
  ]
}`
)

func TestInput(t *testing.T) {
	var requestData RequestData
	err := json.Unmarshal([]byte(requestBody), &requestData)

	assert.NilError(t, err)
	assert.Equal(t, requestData.Images.Containers["tomcat"].Name, "tomcat")
	assert.Equal(t, requestData.Images.Containers["tomcat"].Pointer, "spec/container/0/image")
	assert.Equal(t, requestData.Images.InitContainers["vault"].Name, "vault")
	assert.Equal(t, requestData.Images.InitContainers["vault"].Pointer, "spec/initContainer/0/image")

	assert.Equal(t, len(requestData.Attestations), 2)
	assert.Equal(t, requestData.Attestations[0].ImageReference, "*")
	assert.Equal(t, len(requestData.Attestations[0].Type), 2)
	assert.Equal(t, requestData.Attestations[0].Type[0], "sbom/cyclone-dx")
	assert.Equal(t, requestData.Attestations[1].ImageReference, "844333597536.dkr.ecr.us-west-2.amazonaws.com/kyverno-demo:*")
}
