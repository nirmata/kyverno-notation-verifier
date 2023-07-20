package verifier

import (
	"encoding/json"
	"testing"

	"gotest.tools/assert"
)

var (
	noImagesRequest = `
{
  "images": {
    "containers": {},
    "initContainers": {}
  }
}`

	noAttestationName = `{
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

	noConditionKey = `
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

	noConditionValue = `{
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
            "any" : [
              {
                "key":"{{request.operation}}",
                "operator": "Equals"
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

func Test_RequestValidation(t *testing.T) {
	var noImages, noAttestations, noKey, noValue RequestData

	err := json.Unmarshal([]byte(noImagesRequest), &noImages)
	assert.NilError(t, err)
	err = validateRequestData(&noImages)
	assert.Error(t, err, "atleast one image must be provided")

	err = json.Unmarshal([]byte(noAttestationName), &noAttestations)
	assert.NilError(t, err)
	err = validateRequestData(&noAttestations)
	assert.Error(t, err, "attestation name cannot be empty")

	err = json.Unmarshal([]byte(noConditionKey), &noKey)
	assert.NilError(t, err)
	err = validateRequestData(&noKey)
	assert.Error(t, err, "condtion key cannot be empty")

	err = json.Unmarshal([]byte(noConditionValue), &noValue)
	assert.NilError(t, err)
	err = validateRequestData(&noValue)
	assert.Error(t, err, "condtion value cannot be empty")
}
