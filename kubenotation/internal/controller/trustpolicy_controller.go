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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/go-logr/logr"
	notationv1alpha1 "github.com/nirmata/kyverno-notation-verifier/kubenotation/api/v1alpha1"
	"github.com/nirmata/kyverno-notation-verifier/kubenotation/utils"
	"github.com/pkg/errors"
)

// TrustPolicyReconciler reconciles a TrustPolicy object
type TrustPolicyReconciler struct {
	client.Client
	Scheme            *runtime.Scheme
	CRDChangeInformer *chan struct{}
}

//+kubebuilder:rbac:groups=notation.nirmata.io,resources=trustpolicies,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=notation.nirmata.io,resources=trustpolicies/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=notation.nirmata.io,resources=trustpolicies/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the TrustPolicy object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.14.1/pkg/reconcile
func (r *TrustPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	var trustPolicy notationv1alpha1.TrustPolicy
	if err := r.Get(ctx, req.NamespacedName, &trustPolicy); err != nil {
		log.Info("unable to fetch TrustPolicy", "reason", err.Error())
		return ctrl.Result{}, nil
	}

	if trustPolicy.ObjectMeta.DeletionTimestamp.IsZero() {
		if !controllerutil.ContainsFinalizer(&trustPolicy, utils.FinalizerName) {
			controllerutil.AddFinalizer(&trustPolicy, utils.FinalizerName)
			if err := r.Update(ctx, &trustPolicy); err != nil {
				return ctrl.Result{}, err
			}
		}

		if err := writeTrustPolicy(trustPolicy, log, r.CRDChangeInformer); err != nil {
			return ctrl.Result{}, err
		}

	} else { // handle delete
		if err := deleteTrustPolicy(trustPolicy, log, r.CRDChangeInformer); err != nil {
			return ctrl.Result{}, errors.Wrap(err, "failed to delete trust policy")
		}

		controllerutil.RemoveFinalizer(&trustPolicy, utils.FinalizerName)
		if err := r.Update(ctx, &trustPolicy); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

func writeTrustPolicy(policy notationv1alpha1.TrustPolicy, log logr.Logger, crdChangeChan *chan struct{}) error {
	log.Info("writing trust policy", "name", policy.Name)
	if err := os.MkdirAll(utils.NotationPath, 0700); err != nil {
		return errors.Wrapf(err, "failed to create output directory")
	}

	jsonData, err := json.MarshalIndent(policy.Spec, "  ", " ")
	if err != nil {
		return errors.Wrapf(err, "failed to marshal to JSON")
	}

	trustPolicyName := fmt.Sprintf("%s.json", policy.Name)
	fileName := filepath.Join(utils.NotationPath, trustPolicyName)
	os.WriteFile(fileName, jsonData, 0600)

	log.Info("updated trust policy", "path", fileName)

	select {
	case *crdChangeChan <- struct{}{}:
		log.Info("CRDs updated: sent update request")
	default:
		log.Info("CRDs updated: update request already present")
	}

	return nil
}

func deleteTrustPolicy(policy notationv1alpha1.TrustPolicy, log logr.Logger, crdChangeChan *chan struct{}) error {
	log.Info("deleting trust policy", "name", policy.Name)

	trustPolicyName := fmt.Sprintf("%s.json", policy.Name)
	fileName := filepath.Join(utils.NotationPath, trustPolicyName)
	if err := os.RemoveAll(fileName); err != nil {
		return errors.Wrapf(err, "failed to delete %s", fileName)
	}

	log.Info("deleted trust policy", "path", fileName)

	select {
	case *crdChangeChan <- struct{}{}:
		log.Info("CRDs updated: sent update request")
	default:
		log.Info("CRDs updated: update request already present")
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *TrustPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&notationv1alpha1.TrustPolicy{}).
		Complete(r)
}
