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
)

func Test_RequestValidation(t *testing.T) {
	var requestData RequestData
	err := json.Unmarshal([]byte(noImagesRequest), &requestData)
	assert.NilError(t, err)

	err = validateRequestData(&requestData)
	assert.Error(t, err, "atleast one image must be provided")
}
