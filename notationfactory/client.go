package notationfactory

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/nirmata/kyverno-notation-verifier/kubenotation/utils"
	"github.com/nirmata/kyverno-notation-verifier/types"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/plugin"
	"github.com/notaryproject/notation-go/verifier"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type notationverifierfactory struct {
	verifiers map[string]*notation.Verifier
	log       *zap.SugaredLogger
	lock      sync.Mutex
}

func NewNotationVerifierFactory(logger *zap.SugaredLogger) NotationVeriferFactory {
	return &notationverifierfactory{
		verifiers: make(map[string]*notation.Verifier),
		log:       logger,
	}
}

func (f *notationverifierfactory) clear() {
	f.lock.Lock()
	defer f.lock.Unlock()

	f.verifiers = make(map[string]*notation.Verifier)
	f.log.Info("Notation verifier factory cleared")
}

func (f *notationverifierfactory) RefreshVerifiers() error {
	f.lock.Lock()
	defer f.lock.Unlock()

	f.log.Info("Refreshing notation verifiers")
	verifiers := make(map[string]*notation.Verifier)

	entries, err := os.ReadDir(utils.NotationPath)
	if err != nil {
		f.log.Errorf("failed to read notation directory %v", err)
		return err
	}

	for _, e := range entries {
		f.log.Infof("Reading file in notation directory, %s", e.Name())
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}

		fileName := filepath.Join(utils.NotationPath, e.Name())
		trustPolicy, err := f.loadTrustPolicy(fileName)

		if err != nil {
			f.log.Errorf("failed to load trust policy loaded from file %s", fileName)
			return err
		}
		f.log.Infof("Trust policy loaded from file %s", fileName)
		x509TrustStore := truststore.NewX509TrustStore(dir.ConfigFS())
		f.log.Infof("Trust store loaded")

		verifier, err := verifier.New(trustPolicy, x509TrustStore, plugin.NewCLIManager(dir.PluginFS()))
		if err != nil {
			return err
		}
		trustpolicy := strings.TrimSuffix(fileName, filepath.Ext(fileName))

		verifiers[trustpolicy] = &verifier
		f.log.Infof("Added verifier to the list for trust policy %s", trustPolicy)
	}

	f.clear()
	f.verifiers = verifiers
	f.log.Infof("Successfully updated verifiers")
	return nil
}

func (f *notationverifierfactory) GetVerifier(requestData *types.RequestData) (*notation.Verifier, error) {
	f.lock.Lock()
	defer f.lock.Unlock()

	trustPolicy := requestData.TrustPolicy
	if len(trustPolicy) == 0 {
		trustPolicy = os.Getenv(types.ENV_DEFAULT_TRUST_STORE)
		f.log.Infof("Using default turst policy from env")
	} else {
		f.log.Infof("Using trust policy provided in the request")
	}

	if len(trustPolicy) == 0 {
		return nil, errors.Errorf("no trust store specified, please specify a trust store in request or set %s env", types.ENV_DEFAULT_TRUST_STORE)
	}

	verifier, found := f.verifiers[trustPolicy]
	if !found {
		return nil, errors.Errorf("no trust store found for trust store %s", trustPolicy)
	}
	f.log.Infof("Found notation verifer for trust policy %s", trustPolicy)

	return verifier, nil
}

func (f *notationverifierfactory) loadTrustPolicy(path string) (*trustpolicy.Document, error) {
	fileInfo, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("trust policy is not present %s", path)
		}
		return nil, err
	}

	mode := fileInfo.Mode()
	if mode.IsDir() || mode&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("trust policy is not a regular file (symlinks are not supported)")
	}

	jsonFile, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return nil, fmt.Errorf("unable to read trust policy due to file permissions, please verify the permissions of %s", filepath.Join(dir.UserConfigDir, dir.PathTrustPolicy))
		}
		return nil, err
	}
	defer jsonFile.Close()

	policyDocument := &trustpolicy.Document{}
	err = json.NewDecoder(jsonFile).Decode(policyDocument)
	if err != nil {
		return nil, fmt.Errorf("malformed trust policy")
	}
	return policyDocument, nil
}
