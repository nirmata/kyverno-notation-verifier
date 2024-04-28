package notationfactory

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/nirmata/kyverno-notation-verifier/kubenotation/utils"
	"github.com/nirmata/kyverno-notation-verifier/pkg/types"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/plugin"
	"github.com/notaryproject/notation-go/verifier"
	"github.com/notaryproject/notation-go/verifier/truststore"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type NotationVeriferFactory interface {
	// RefreshVerifiers will remove all the existing verifiers and create new ones using the trust policies in notation directory
	RefreshVerifiers() error

	// GetVerifier returns a verifier based on the trust policy in request or the default trustpolicy in trust policy env
	GetVerifier(requestData *types.VerificationRequest) (*notation.Verifier, error)
}

func NewNotationVerifierFactory(logger *zap.SugaredLogger) NotationVeriferFactory {
	return &notationverifierfactory{
		verifiers: make(map[string]*notation.Verifier),
		log:       logger,
	}
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
	f.log.Infof("Files in notation directory, %v", entries)

	for _, e := range entries {
		f.log.Infof("Reading file in notation directory, %s", e.Name())
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			f.log.Infof("Entry is a directory %s", e.Name())
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
		trustpolicyName := strings.TrimSuffix(filepath.Base(fileName), filepath.Ext(fileName))

		verifiers[trustpolicyName] = &verifier
		f.log.Infof("Added verifier to the list for trust policy %s", trustpolicyName)
	}

	f.clear()
	f.verifiers = verifiers
	f.log.Infof("Successfully updated verifiers")
	return nil
}

func (f *notationverifierfactory) GetVerifier(requestData *types.VerificationRequest) (*notation.Verifier, error) {
	f.lock.Lock()
	defer f.lock.Unlock()

	trustPolicy := requestData.TrustPolicy
	if len(trustPolicy) == 0 {
		trustPolicy = os.Getenv(types.ENV_DEFAULT_TRUST_POLICY)
		f.log.Infof("Using default trust policy from env %s", trustPolicy)
	} else {
		f.log.Infof("Using trust policy provided in the request %s", trustPolicy)
	}

	if len(trustPolicy) == 0 {
		return nil, errors.Errorf("no trust policy specified, please specify a trust policy in request or set %s env", types.ENV_DEFAULT_TRUST_POLICY)
	}

	verifier, found := f.verifiers[trustPolicy]
	if !found {
		return nil, errors.Errorf("no trust policy found for trust policy %s", trustPolicy)
	}
	f.log.Infof("Found notation verifer for trust policy %s", trustPolicy)

	return verifier, nil
}
