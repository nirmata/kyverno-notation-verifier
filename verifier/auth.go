package verifier

import (
	"context"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	kauth "github.com/google/go-containerregistry/pkg/authn/kubernetes"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	"oras.land/oras-go/v2/registry"
)

func (v *verifier) getAuthConfig(ctx context.Context, ref registry.Reference) (*authn.AuthConfig, error) {
	if v.imagePullSecrets != "" {
		return v.getAuthFromSecret(ctx, ref)
	}

	if v.providerAuthConfigResolver != nil {
		return v.providerAuthConfigResolver(ctx, ref)
	}

	return nil, nil
}

func (v *verifier) getAuthFromSecret(ctx context.Context, ref registry.Reference) (*authn.AuthConfig, error) {
	if v.imagePullSecrets == "" {
		return nil, errors.Errorf("secret not configured")
	}

	v.logger.Infof("fetching credentials from secret %s...", v.imagePullSecrets)
	var secrets []corev1.Secret
	for _, imagePullSecret := range strings.Split(v.imagePullSecrets, ",") {
		secret, err := v.secretLister.Get(imagePullSecret)
		if err != nil {
			return nil, err
		}

		secrets = append(secrets, *secret)
	}

	keychain, err := kauth.NewFromPullSecrets(ctx, secrets)
	if err != nil {
		return nil, err
	}

	authenticator, err := keychain.Resolve(&imageResource{ref})
	if err != nil {
		return nil, err
	}

	authConfig, err := authenticator.Authorization()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get auth config for %s", ref.String())
	}

	return authConfig, nil
}

type imageResource struct {
	ref registry.Reference
}

func (ir *imageResource) String() string {
	return ir.ref.String()
}

func (ir *imageResource) RegistryStr() string {
	return ir.ref.Registry
}
