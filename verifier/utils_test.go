package verifier

import (
	"encoding/json"
	"testing"

	"github.com/nirmata/kyverno-notation-verifier/types"
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
	var requestData types.RequestData
	err := json.Unmarshal([]byte(noImagesRequest), &requestData)
	assert.NilError(t, err)

	err = validateRequestData(&requestData)
	assert.Error(t, err, "atleast one image must be provided")
}
