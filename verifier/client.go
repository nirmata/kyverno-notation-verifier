package verifier

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/google/go-containerregistry/pkg/authn"
	enginecontext "github.com/kyverno/kyverno/pkg/engine/context"
	"github.com/nirmata/kyverno-notation-verifier/pkg/cache"
	"github.com/nirmata/kyverno-notation-verifier/pkg/notationfactory"
	"github.com/nirmata/kyverno-notation-verifier/types"
	"github.com/nirmata/kyverno-notation-verifier/verifier/internal"
	"go.uber.org/zap"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"oras.land/oras-go/v2/registry"
)

type Verifier interface {
	// HandleCheckImages is a handler function that takes Kyverno images variable in body and returns JSONPatch compatible object in response
	HandleCheckImages(w http.ResponseWriter, r *http.Request)

	UpdateNotationVerfier() error
	// Shuts down all the factories before exiting
	Stop()
}

type verifier struct {
	logger                     *zap.SugaredLogger
	kubeClient                 *kubernetes.Clientset
	notationVerifierFactory    notationfactory.NotationVeriferFactory
	informerFactory            kubeinformers.SharedInformerFactory
	secretLister               corev1listers.SecretNamespaceLister
	configMapLister            corev1listers.ConfigMapNamespaceLister
	providerAuthConfigResolver func(context.Context, registry.Reference) (authn.AuthConfig, error)
	imagePullSecrets           string
	insecureRegistry           bool
	pluginConfigMap            string
	maxSignatureAttempts       int
	maxCacheSize               int64
	useCache                   bool
	reviewToken                bool
	maxCacheTTL                time.Duration
	debug                      bool
	stopCh                     chan struct{}
	engineContext              enginecontext.Interface
	cache                      cache.Cache
}

type verifierOptsFunc func(*verifier)

func WithImagePullSecrets(secrets string) verifierOptsFunc {
	return func(v *verifier) {
		v.imagePullSecrets = secrets
	}
}

func WithInsecureRegistry(insecureRegistry bool) verifierOptsFunc {
	return func(v *verifier) {
		v.insecureRegistry = insecureRegistry
	}
}

func WithPluginConfig(pluginConfigMap string) verifierOptsFunc {
	return func(v *verifier) {
		v.pluginConfigMap = pluginConfigMap
	}
}

func WithMaxSignatureAttempts(maxSignatureAttempts int) verifierOptsFunc {
	return func(v *verifier) {
		v.maxSignatureAttempts = maxSignatureAttempts
	}
}

func WithMaxCacheSize(maxCacheSize int64) verifierOptsFunc {
	return func(v *verifier) {
		v.maxCacheSize = maxCacheSize
	}
}

func WithMaxCacheTTL(maxCacheTTL time.Duration) verifierOptsFunc {
	return func(v *verifier) {
		v.maxCacheTTL = maxCacheTTL
	}
}

func WithCacheEnabled(useCache bool) verifierOptsFunc {
	return func(v *verifier) {
		v.useCache = useCache
	}
}

func WithTokenReviewEnabled(enableTokenReview bool) verifierOptsFunc {
	return func(v *verifier) {
		v.reviewToken = enableTokenReview
	}
}

func WithEnableDebug(debug bool) verifierOptsFunc {
	return func(v *verifier) {
		v.debug = debug
	}
}

func WithProviderAuthConfigResolver(providerAuthConfigResolver func(context.Context, registry.Reference) (authn.AuthConfig, error)) verifierOptsFunc {
	return func(v *verifier) {
		v.providerAuthConfigResolver = providerAuthConfigResolver
	}
}

func NewVerifier(logger *zap.SugaredLogger, opts ...verifierOptsFunc) Verifier {
	var verifier *verifier
	var err error

	initVerifier := func() error {
		verifier, err = newVerifier(logger, opts...)
		return err
	}

	if err := backoff.Retry(initVerifier, backoff.NewExponentialBackOff()); err != nil {
		logger.Fatalf("initialization failed, error: %v", err)
	}

	return verifier
}

func (v *verifier) HandleCheckImages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	if v.reviewToken {
		reqToken := r.Header.Get("Authorization")
		if len(reqToken) == 0 {
			http.Error(w, "Authorization header not supplied", http.StatusUnauthorized)
			return
		}
		splitToken := strings.Split(reqToken, "Bearer ")
		if len(splitToken) == 0 {
			http.Error(w, "No token provided in the header", http.StatusUnauthorized)
			return
		}
		reqToken = splitToken[1]

		tr := authv1.TokenReview{
			Spec: authv1.TokenReviewSpec{
				Token: reqToken,
			},
		}

		result, err := v.kubeClient.AuthenticationV1().TokenReviews().Create(context.TODO(), &tr, metav1.CreateOptions{})
		if err != nil {
			v.logger.Infof("failed to verify auth token %v", err)
			http.Error(w, err.Error(), http.StatusNotAcceptable)
			return
		}

		if !result.Status.Authenticated || result.Status.User.Username != "system:serviceaccount:kyverno:kyverno-admission-controller" {
			v.logger.Infof("Token is not authorized %+v", *result)
			http.Error(w, "Token is not authorized", http.StatusNotAcceptable)
			return
		}

		v.logger.Infof("Token is authorized %+v", *result)
	}

	var requestData types.RequestData
	//err := json.NewDecoder(r.Body).Decode(&requestData)
	raw, _ := io.ReadAll(r.Body)

	err := json.Unmarshal(raw, &requestData)
	if err != nil {
		v.logger.Infof("failed to decode %s: %v", string(raw), err)
		http.Error(w, err.Error(), http.StatusNotAcceptable)
		return
	}
	v.logger.Infof("Request recieved with data=%+v", requestData)

	var verificationPayload *types.VerificationRequest
	if verificationPayload, err = internal.ProcessRequestData(&requestData); err != nil {
		v.logger.Infof("Missing required data: %v", err)
		http.Error(w, err.Error(), http.StatusNotAcceptable)
		return
	}

	if reflect.ValueOf(verificationPayload.Images).IsZero() {
		v.logger.Infof("images variable not found")
		http.Error(w, "missing required parameter 'images'", http.StatusNotAcceptable)
		return
	} else {
		ctx := context.Background()

		responseData, err := v.verifyImagesAndAttestations(ctx, verificationPayload)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if !responseData.Verified {
			http.Error(w, responseData.ErrorMessage, http.StatusNotAcceptable)
			return
		}

		data, err := json.MarshalIndent(responseData, "  ", "  ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if !responseData.Verified {
			http.Error(w, responseData.ErrorMessage, http.StatusNotAcceptable)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(data)
	}
}

func (v *verifier) UpdateNotationVerfier() error {
	if err := v.notationVerifierFactory.RefreshVerifiers(); err != nil {
		v.logger.Errorf("notation verifier creation failed, not updating verifiers: %v", err)
		return err
	}

	v.cache.Clear()
	return nil
}

func (v *verifier) Stop() {
	v.logger.Sync()
	v.informerFactory.Shutdown()
	v.stopCh <- struct{}{}
}
