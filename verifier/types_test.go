package verifier

import (
	"encoding/json"
	"testing"

	v1 "github.com/kyverno/kyverno/api/kyverno/v1"
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
        {
          "name": "sbom/cyclone-dx",
          "conditions": {
            "all" : [
              {
                "key":"{{request.operation}}",
                "operator": "Equals",
                "value":"UPDATE"
              }
            ]
          } 
        },
        {
          "name": "application/sarif+json",
          "conditions": {
            "all" : [
              {
                "key":"{{request.operation}}",
                "operator": "Equals",
                "value":"UPDATE"
              }
            ]
          } 
        }
      ]
    },
    {
      "imageReference": "844333597536.dkr.ecr.us-west-2.amazonaws.com/kyverno-demo:*",
      "type": [
        {
          "name": "application/vnd.cyclonedx",
          "conditions": {
            "all" : [
              {
                "key":"{{request.operation}}",
                "operator": "Equals",
                "value":"UPDATE"
              }
            ]
          } 
        }
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
	assert.Equal(t, len(requestData.Attestations[0].Type[0].Conditions.AnyConditions), 0)
	assert.Equal(t, len(requestData.Attestations[0].Type[0].Conditions.AllConditions), 1)
	assert.Equal(t, requestData.Attestations[0].Type[0].Conditions.AllConditions[0].Operator, v1.ConditionOperator("Equals"))
	assert.Equal(t, requestData.Attestations[0].Type[0].Name, "sbom/cyclone-dx")
	assert.Equal(t, requestData.Attestations[1].ImageReference, "844333597536.dkr.ecr.us-west-2.amazonaws.com/kyverno-demo:*")
}
