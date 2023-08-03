package verifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-logr/zapr"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	gcrremote "github.com/google/go-containerregistry/pkg/v1/remote"
	kyvernov1 "github.com/kyverno/kyverno/api/kyverno/v1"
	kyvernocfg "github.com/kyverno/kyverno/pkg/config"
	enginecontext "github.com/kyverno/kyverno/pkg/engine/context"
	"github.com/kyverno/kyverno/pkg/engine/jmespath"
	"github.com/kyverno/kyverno/pkg/engine/variables"
	"github.com/nirmata/kyverno-notation-verifier/pkg/cache"
	"github.com/nirmata/kyverno-notation-verifier/pkg/notationfactory"
	"github.com/nirmata/kyverno-notation-verifier/types"
	"github.com/notaryproject/notation-go"
	notationlog "github.com/notaryproject/notation-go/log"
	notationregistry "github.com/notaryproject/notation-go/registry"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"go.uber.org/multierr"
	"go.uber.org/zap"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	ctrl "sigs.k8s.io/controller-runtime"
)

func newVerifier(logger *zap.SugaredLogger, opts ...verifierOptsFunc) (*verifier, error) {
	v := &verifier{
		logger: logger,
	}

	config, err := ctrl.GetConfig()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get Kubernetes config")
	}

	v.kubeClient, err = kubernetes.NewForConfig(config)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create Kubernetes client")
	}

	v.notationVerifierFactory = notationfactory.NewNotationVerifierFactory(logger)
	err = v.notationVerifierFactory.RefreshVerifiers()
	if err != nil {
		v.logger.Errorf("failed to create notation verifiers, error: %v", err)
		return nil, err
	}
	v.logger.Info("notation verifier created")

	v.cache, err = cache.New(cache.WithCacheEnabled(v.useCache), cache.WithCleanupWindow(v.cacheCleanupTime), cache.WithMaxSize(v.maxCacheSize), cache.WithTTLDuration(v.maxCacheTTL))
	if err != nil {
		return nil, errors.Wrap(err, "failed to create cache client")
	}
	v.logger.Info("cache created")

	namespace := os.Getenv("POD_NAMESPACE")
	v.informerFactory = kubeinformers.NewSharedInformerFactoryWithOptions(v.kubeClient, 15*time.Minute, kubeinformers.WithNamespace(namespace))
	v.secretLister = v.informerFactory.Core().V1().Secrets().Lister().Secrets(namespace)
	v.configMapLister = v.informerFactory.Core().V1().ConfigMaps().Lister().ConfigMaps(namespace)

	for _, o := range opts {
		o(v)
	}

	var jp = jmespath.New(kyvernocfg.NewDefaultConfiguration(false))
	v.engineContext = enginecontext.NewContext(jp)

	v.logger.Infow("initialized", "namespace", namespace, "secrets", v.imagePullSecrets,
		"insecureRegistry", v.insecureRegistry)

	v.stopCh = make(chan struct{})
	go v.informerFactory.Start(v.stopCh)

	return v, nil
}

func (v *verifier) verifyImagesAndAttestations(ctx context.Context, requestData *types.RequestData) ([]byte, error) {
	response := NewResponse()
	verificationFailed := false
	images := requestData.Images

	notationVerifier, err := v.notationVerifierFactory.GetVerifier(requestData)
	if err != nil {
		v.logger.Errorf("failed to create notation verifier: %s", err.Error())
		return response.VerificationFailed(fmt.Sprintf("failed to create notation verifier: %s", err.Error()))
	}

	if !verificationFailed {
		for _, image := range images.Containers {
			result, err := v.verifyImageInfo(ctx, notationVerifier, image, v.getTrustPolicy(requestData))
			if err != nil {
				v.logger.Errorf("failed to verify container %s: %s", image.Name, err.Error())
				return response.VerificationFailed(fmt.Sprintf("failed to verify container %s: %v", image.Name, err.Error()))
			}
			response.AddImage(result)
		}
		v.logger.Infof("verified %d containers ", images.Containers)
	}

	if !verificationFailed {
		for _, image := range images.InitContainers {
			result, err := v.verifyImageInfo(ctx, notationVerifier, image, v.getTrustPolicy(requestData))
			if err != nil {
				v.logger.Errorf("failed to verify init container %s: %s", image.Name, err.Error())
				return response.VerificationFailed(fmt.Sprintf("failed to verify init container %s: %v", image.Name, err.Error()))
			}
			response.AddImage(result)
		}
		v.logger.Infof("verified %d initContainers", images.InitContainers)
	}

	if !verificationFailed {
		for _, image := range images.EphemeralContainers {
			result, err := v.verifyImageInfo(ctx, notationVerifier, image, v.getTrustPolicy(requestData))
			if err != nil {
				v.logger.Errorf("failed to verify ephemeral container %s: %s", image.Name, err.Error())
				return response.VerificationFailed(fmt.Sprintf("failed to verify ephemeral container: %s: %v", image.Name, err.Error()))
			}
			response.AddImage(result)
		}
		v.logger.Infof("verified %d ephemeralContainers", images.EphemeralContainers)
	}

	if err := response.BuildAttestationList(requestData.Attestations); err != nil {
		return nil, errors.Wrapf(err, "failed to create attestation list")
	}
	v.logger.Infof("built attestation list", response.GetImageList())

	if err := v.verifyAttestations(ctx, notationVerifier, response, v.getTrustPolicy(requestData)); err != nil {
		return response.VerificationFailed(fmt.Sprintf("failed to verify attestatations: %v", err.Error()))
	}

	return response.VerificationSucceeded("")
}

func (v *verifier) verifyAttestations(ctx context.Context, notationVerifier *notation.Verifier, response Response, trustPolicy string) error {
	v.logger.Infof("verifying attestations %v", response.GetImageList())
	for image, list := range response.GetImageList() {
		if err := v.verifyAttestation(ctx, notationVerifier, image, list, trustPolicy); err != nil {
			return errors.Wrapf(err, "failed to verify attestations")
		}
	}
	return nil
}

func (v *verifier) verifyAttestation(ctx context.Context, notationVerifier *notation.Verifier, image string, attestationList types.AttestationList, trustPolicy string) error {
	v.logger.Infof("verifying attestation, image=%s; attestations=%v", image, attestationList)
	if len(attestationList) == 0 {
		return nil
	}

	remoteOpts, err := v.getRemoteOpts(ctx, image)
	if err != nil {
		return errors.Wrapf(err, "failed to get gcr remote opts")
	}

	ref, err := name.ParseReference(image)
	if err != nil {
		return errors.Wrapf(err, "failed to parse image reference: %s", image)
	}

	refDesc, err := gcrremote.Head(ref, remoteOpts...)
	if err != nil {
		return errors.Wrapf(err, "failed to get gcr remote head")
	}

	referrers, err := gcrremote.Referrers(ref.Context().Digest(refDesc.Digest.String()), remoteOpts...)
	if err != nil {
		return errors.Wrapf(err, "failed to get gcr remote referrers")
	}

	referrersDescs, err := referrers.IndexManifest()
	if err != nil {
		return err
	}

	for _, referrer := range referrersDescs.Manifests {
		if _, found := attestationList[referrer.ArtifactType]; !found {
			continue
		}

		v.logger.Infof("verifying attestation, image=%s; type=%s", image, referrer.ArtifactType)

		conditions := attestationList[referrer.ArtifactType]

		if found := v.cache.GetAttestation(trustPolicy, image, referrer.ArtifactType, conditions); found {
			v.logger.Infof("Entry for the attestation found in cache, skipping image=%s; type=%s", image, referrer.ArtifactType)
			continue
		}
		referrerRef := v.getReference(referrer, ref)

		_, err := v.verifyReferences(ctx, notationVerifier, referrerRef)
		if err != nil {
			return errors.Wrapf(err, "failed to get referrer of artifact type %s %s %s", ref.String(), referrer.Digest.String(), referrer.ArtifactType)
		}

		if len(conditions) != 0 {
			if err := v.verifyConditions(ctx, ref, referrer, conditions, remoteOpts...); err != nil {
				return errors.Wrapf(err, "failed to verify conditions %s %s", ref.String(), referrer.Digest.String())
			}
		}

		if err := v.cache.AddAttestation(trustPolicy, image, referrer.ArtifactType, conditions); err != nil {
			return errors.Wrapf(err, "failed to add attestation to the cache image=%s, digest=%s", ref.String(), referrer.Digest.String())
		}
	}

	return nil
}

func (v *verifier) verifyConditions(ctx context.Context, repoRef name.Reference, desc v1.Descriptor, conditions []kyvernov1.AnyAllConditions, options ...gcrremote.Option) error {
	v.engineContext.Checkpoint()
	defer v.engineContext.Restore()

	payload, err := v.extractPayload(ctx, repoRef, desc, options...)
	if err != nil {
		return err
	}

	if err := enginecontext.AddJSONObject(v.engineContext, payload); err != nil {
		return fmt.Errorf("failed to add Statement to the context: %w", err)
	}

	val, msg, err := variables.EvaluateAnyAllConditions(zapr.NewLogger(v.logger.Desugar()), v.engineContext, conditions)
	if err != nil {
		return err
	}
	if !val {
		return errors.Errorf("failed to evaluate conditions: %s", msg)
	}
	v.logger.Infof("successfully verified condition for image %s", repoRef.String())
	return nil
}

func (v *verifier) extractPayload(ctx context.Context, repoRef name.Reference, desc v1.Descriptor, options ...gcrremote.Option) (map[string]interface{}, error) {
	refStr := repoRef.Context().RegistryStr() + "/" + repoRef.Context().RepositoryStr() + "@" + desc.Digest.String()
	ref, err := name.ParseReference(refStr)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse image reference: %s", refStr)
	}

	manifestDesc, err := gcrremote.Get(ref, options...)
	if err != nil {
		return nil, errors.Wrapf(err, "error in fetching statement")
	}
	manifestBytes, err := manifestDesc.RawManifest()
	if err != nil {
		return nil, errors.Wrapf(err, "error in fetching statement")
	}
	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, err
	}

	if len(manifest.Layers) == 0 {
		return nil, errors.Errorf("no predicate found: %+v", manifest)
	}
	if len(manifest.Layers) > 1 {
		return nil, errors.Errorf("multiple layers in predicate not supported: %+v", manifest)
	}
	payloadDesc := manifest.Layers[0]

	layer, err := gcrremote.Layer(repoRef.Context().Digest(payloadDesc.Digest.String()))
	if err != nil {
		return nil, err
	}
	ioPredicate, err := layer.Uncompressed()
	if err != nil {
		return nil, err
	}
	predicateBytes := new(bytes.Buffer)
	_, err = predicateBytes.ReadFrom(ioPredicate)
	if err != nil {
		return nil, err
	}

	predicate := make(map[string]interface{})
	if err := json.Unmarshal(predicateBytes.Bytes(), &predicate); err != nil {
		return nil, err
	}
	v.logger.Infof("successfully extracted payload for image %s", repoRef.String())
	return predicate, nil
}

func (v *verifier) verifyImageInfo(ctx context.Context, notationVerifier *notation.Verifier, image types.ImageInfo, trustPolicy string) (*types.ImageInfo, error) {
	if img, found := v.cache.GetImage(trustPolicy, image.String()); found {
		v.logger.Infof("Entry for the image found in cache, skipping image=%s; trustpolicy=%s", image, trustPolicy)
		return img, nil
	}
	v.logger.Infof("verifying image infos %+v", image)
	digest, err := v.verifyReferences(ctx, notationVerifier, image.String())
	if err != nil {
		v.logger.Errorf("verification failed for image %s: %v", image, err)
		return nil, errors.Wrapf(err, "failed to verify image %s", image)
	}
	image.Digest = digest
	if err := v.cache.AddImage(trustPolicy, image.String(), image); err != nil {
		return nil, errors.Wrapf(err, "failed to add image to the cache %s", image)
	}
	return &image, nil
}

func (v *verifier) verifyReferences(ctx context.Context, notationVerifier *notation.Verifier, image string) (string, error) {
	v.logger.Infof("verifying image %s", image)
	repo, reference, err := v.parseReferenceAndResolveDigest(ctx, image)
	if err != nil {
		return "", errors.Wrapf(err, "failed to resolve digest")
	}

	pluginConfig := map[string]string{}
	if v.pluginConfigMap != "" {
		cm, err := v.configMapLister.Get(v.pluginConfigMap)
		if err != nil {
			return "", errors.Wrapf(err, "failed to fetch plugin configmap %s", v.pluginConfigMap)
		}

		for k, v := range cm.Data {
			pluginConfig[k] = v
		}
	}

	opts := notation.VerifyOptions{
		ArtifactReference:    reference.String(),
		MaxSignatureAttempts: v.maxSignatureAttempts,
		PluginConfig:         pluginConfig,
	}

	nlog := notationlog.WithLogger(ctx, notationlog.Discard)
	if v.debug {
		pluginConfig["debug"] = "true"
		nlog = notationlog.WithLogger(ctx, v.logger)
	}

	desc, outcomes, err := notation.Verify(nlog, *notationVerifier, repo, opts)
	if err != nil {
		return "", err
	}

	var errs []error
	for _, o := range outcomes {
		if o.Error != nil {
			errs = append(errs, o.Error)
		}
	}

	if len(errs) > 0 {
		err := multierr.Combine(errs...)
		return "", err
	}

	v.logger.Infof("successfully verified image %s digest %s", image, desc.Digest.String())

	return desc.Digest.String(), nil
}

func (v *verifier) getRemoteOpts(ctx context.Context, ref string) ([]gcrremote.Option, error) {
	if !strings.Contains(ref, "/") {
		ref = "docker.io/library/" + ref
	}

	if !strings.Contains(ref, ":") {
		ref = ref + ":latest"
	}

	parsedRef, err := registry.ParseReference(ref)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse reference %s", ref)
	}

	authConfig, err := v.getAuthConfig(ctx, parsedRef)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to retrieve credentials")
	}

	authenticator := authn.FromConfig(authConfig)

	remoteOpts := []gcrremote.Option{}
	remoteOpts = append(remoteOpts, gcrremote.WithAuth(authenticator))

	pusher, err := gcrremote.NewPusher(remoteOpts...)
	if err != nil {
		return nil, err
	}
	remoteOpts = append(remoteOpts, gcrremote.Reuse(pusher))

	puller, err := gcrremote.NewPuller(remoteOpts...)
	if err != nil {
		return nil, err
	}
	remoteOpts = append(remoteOpts, gcrremote.Reuse(puller))

	return remoteOpts, nil
}

func (v *verifier) parseReferenceAndResolveDigest(ctx context.Context, ref string) (notationregistry.Repository, registry.Reference, error) {
	if !strings.Contains(ref, "/") {
		ref = "docker.io/library/" + ref
	}

	if !strings.Contains(ref, ":") {
		ref = ref + ":latest"
	}

	parsedRef, err := registry.ParseReference(ref)
	if err != nil {
		return nil, registry.Reference{}, errors.Wrapf(err, "failed to parse reference %s", ref)
	}

	authClient, plainHTTP, err := v.getAuthClient(ctx, parsedRef)
	if err != nil {
		return nil, registry.Reference{}, errors.Wrapf(err, "failed to retrieve credentials")
	}

	repo, err := remote.NewRepository(ref)
	if err != nil {
		return nil, registry.Reference{}, errors.Wrapf(err, "failed to initialize repository")
	}

	repo.PlainHTTP = plainHTTP
	repo.Client = authClient
	repository := notationregistry.NewRepository(repo)

	parsedRef, err = v.resolveDigest(repository, parsedRef)
	if err != nil {
		return nil, registry.Reference{}, errors.Wrapf(err, "failed to resolve digest")
	}

	return repository, parsedRef, nil
}

func (v *verifier) getAuthClient(ctx context.Context, ref registry.Reference) (*auth.Client, bool, error) {
	authConfig, err := v.getAuthConfig(ctx, ref)
	if err != nil {
		return nil, false, err
	}

	credentials := auth.Credential{
		Username:     authConfig.Username,
		Password:     authConfig.Password,
		AccessToken:  authConfig.IdentityToken,
		RefreshToken: authConfig.RegistryToken,
	}

	authClient := &auth.Client{
		Credential: func(ctx context.Context, registry string) (auth.Credential, error) {
			switch registry {
			default:
				return credentials, nil
			}
		},
		Cache:    auth.NewCache(),
		ClientID: "notation",
	}

	authClient.SetUserAgent("kyverno.io")
	return authClient, false, nil
}

func (v *verifier) resolveDigest(repo notationregistry.Repository, ref registry.Reference) (registry.Reference, error) {
	if isDigestReference(ref.String()) {
		return ref, nil
	}

	// Resolve tag reference to digest reference.
	manifestDesc, err := v.getManifestDescriptorFromReference(repo, ref.String())
	if err != nil {
		return registry.Reference{}, err
	}

	ref.Reference = manifestDesc.Digest.String()
	return ref, nil
}

func isDigestReference(reference string) bool {
	parts := strings.SplitN(reference, "/", 2)
	if len(parts) == 1 {
		return false
	}

	index := strings.Index(parts[1], "@")
	return index != -1
}

func (v *verifier) getManifestDescriptorFromReference(repo notationregistry.Repository, reference string) (ocispec.Descriptor, error) {
	ref, err := registry.ParseReference(reference)
	if err != nil {
		return ocispec.Descriptor{}, err
	}

	return repo.Resolve(context.Background(), ref.ReferenceOrDefault())
}

func (v *verifier) getReference(desc v1.Descriptor, ref name.Reference) string {

	return ref.Context().RegistryStr() + "/" + ref.Context().RepositoryStr() + "@" + desc.Digest.String()

}

func (v *verifier) getTrustPolicy(req *types.RequestData) string {
	trustPolicy := req.TrustPolicy
	if len(trustPolicy) == 0 {
		trustPolicy = os.Getenv(types.ENV_DEFAULT_TRUST_POLICY)
	}
	return trustPolicy
}
