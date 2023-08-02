package notationfactory

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"sync"

	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type notationverifierfactory struct {
	verifiers map[string]*notation.Verifier
	log       *zap.SugaredLogger
	lock      sync.Mutex
}

func (f *notationverifierfactory) clear() {
	f.verifiers = make(map[string]*notation.Verifier)
	f.log.Info("Notation verifier factory cleared")
}

func (f *notationverifierfactory) loadTrustPolicy(path string) (*trustpolicy.Document, error) {
	f.log.Infof("Loading trust policy path=%s", path)
	fileInfo, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("trust policy is not present %s", path)
		}
		return nil, err
	}

	mode := fileInfo.Mode()
	if mode.IsDir() || mode&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("trust policy is not a regular file (symlinks are not supported) path: %s", path)
	}

	jsonFile, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return nil, fmt.Errorf("unable to read trust policy due to file permissions, please verify the permissions of %s", path)
		}
		return nil, err
	}
	defer jsonFile.Close()

	policyDocument := &trustpolicy.Document{}
	err = json.NewDecoder(jsonFile).Decode(policyDocument)
	if err != nil {
		return nil, fmt.Errorf("malformed trust policy path: %s", path)
	}
	return policyDocument, nil
}
