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

package kubenotation

import (

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.

	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/go-logr/logr"
	notationv1alpha1 "github.com/nirmata/kyverno-notation-verifier/kubenotation/api/v1alpha1"
	"github.com/nirmata/kyverno-notation-verifier/kubenotation/internal/controller"
	"github.com/pkg/errors"
	//+kubebuilder:scaffold:imports
)

var (
	scheme = runtime.NewScheme()
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(notationv1alpha1.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

type SetupResult struct {
	mgr                 *manager.Manager
	trustPolicyModified *chan struct{}
}

func Setup(logger logr.Logger, metricsAddr string, probeAddr string, enableLeaderElection bool) (*SetupResult, error) {
	ctrl.SetLogger(logger)
	logger = logger.WithName("setup")

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		MetricsBindAddress:     metricsAddr,
		Port:                   9443,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "d94abea7.nirmata.io",
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		// LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		logger.Error(err, "unable to start manager")
		return nil, errors.Wrapf(err, "unable to start manager")
	}

	tpChan := make(chan struct{}, 1)
	if err = (&controller.TrustPolicyReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		TpChan: &tpChan,
	}).SetupWithManager(mgr); err != nil {
		logger.Error(err, "unable to create controller", "controller", "TrustPolicy")
		return nil, errors.Wrapf(err, "unable to create controller TrustPolicy")
	}
	if err = (&controller.TrustStoreReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		TpChan: &tpChan,
	}).SetupWithManager(mgr); err != nil {
		logger.Error(err, "unable to create controller", "controller", "TrustStore")
		return nil, errors.Wrapf(err, "unable to create controller TrustStore")
	}
	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		logger.Error(err, "unable to set up health check")
		return nil, errors.Wrapf(err, "unable to set up health check")
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		logger.Error(err, "unable to set up ready check")
		return nil, errors.Wrapf(err, "unable to set up ready check")
	}

	// logger.Info("starting manager")
	// if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
	// 	logger.Error(err, "problem running manager")
	// 	return nil, errors.Wrapf(err, "problem running manager")
	// }

	return &SetupResult{
		mgr:                 &mgr,
		trustPolicyModified: &tpChan,
	}, nil
}
