/*
Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"os"
	"path/filepath"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/go-logr/logr"
	notationv1alpha1 "github.com/nirmata/kyverno-notation-verifier/kubenotation/api/v1alpha1"
	"github.com/pkg/errors"
)

// TrustStoreReconciler reconciles a TrustStore object
type TrustStoreReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	CRDChanged *chan struct{}
}

//+kubebuilder:rbac:groups=notation.nirmata.io,resources=truststores,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=notation.nirmata.io,resources=truststores/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=notation.nirmata.io,resources=truststores/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the TrustStore object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.14.1/pkg/reconcile
func (r *TrustStoreReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	var trustStore notationv1alpha1.TrustStore
	if err := r.Get(ctx, req.NamespacedName, &trustStore); err != nil {
		log.Info("unable to fetch TrustStore", "reason", err.Error())
		return ctrl.Result{}, nil
	}

	if trustStore.ObjectMeta.DeletionTimestamp.IsZero() {
		if !controllerutil.ContainsFinalizer(&trustStore, finalizerName) {
			controllerutil.AddFinalizer(&trustStore, finalizerName)
			if err := r.Update(ctx, &trustStore); err != nil {
				return ctrl.Result{}, err
			}
		}

		if err := writeTrustStore(trustStore, log, r.CRDChanged); err != nil {
			return ctrl.Result{}, errors.Wrap(err, "failed to update trust store")
		}

	} else {
		if err := deleteTrustStore(trustStore, log, r.CRDChanged); err != nil {
			return ctrl.Result{}, errors.Wrap(err, "failed to delete trust store")
		}

		controllerutil.RemoveFinalizer(&trustStore, finalizerName)
		if err := r.Update(ctx, &trustStore); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

func writeTrustStore(store notationv1alpha1.TrustStore, log logr.Logger, crdChangeChan *chan struct{}) error {
	tsPath := filepath.Join(notationPath, trustStorePath, store.Spec.Type, store.Spec.TrustStoreName)
	if err := os.MkdirAll(tsPath, 0700); err != nil {
		return errors.Wrapf(err, "failed to create output directory")
	}

	certFile := filepath.Join(tsPath, "certificates.crt")
	os.WriteFile(certFile, []byte(store.Spec.CABundle), 0600)
	log.Info("updated trust store", "path", certFile)

	select {
	case *crdChangeChan <- struct{}{}:
		log.Info("CRDs updated: sent update request")
	default:
		log.Info("CRDs updated: update request already present")
	}

	return nil
}

func deleteTrustStore(store notationv1alpha1.TrustStore, log logr.Logger, crdChangeChan *chan struct{}) error {
	tsPath := filepath.Join(notationPath, trustStorePath, store.Spec.Type, store.Spec.TrustStoreName)
	if err := os.RemoveAll(tsPath); err != nil {
		return errors.Wrapf(err, "failed to delete %s", tsPath)
	}

	log.Info("deleted trust store", "path", tsPath)

	select {
	case *crdChangeChan <- struct{}{}:
		log.Info("CRDs updated: sent update request")
	default:
		log.Info("CRDs updated: update request already present")
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *TrustStoreReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&notationv1alpha1.TrustStore{}).
		Complete(r)
}
