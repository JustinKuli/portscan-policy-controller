/*
Copyright 2022.

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

package controllers

import (
	"context"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	policyv1alpha1 "github.com/JustinKuli/portscan-policy-controller/api/v1alpha1"
)

const (
	ControllerName = "port-scan-policy-controller"
	ScanTimeout    = 10 * time.Minute
)

var (
	log = ctrl.Log.WithName(ControllerName)

	// activeScans is keyed by Policy's NamespacedNames, and its values are used
	// to cancel current and future scans when the Policy is updated or deleted.
	activeScans    = make(map[string]context.CancelFunc)
	activeScansMux = sync.Mutex{}
)

// PortScanPolicyReconciler reconciles a PortScanPolicy object
type PortScanPolicyReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// blank assignment to verify that PortScanPolicyReconciler implements reconcile.Reconciler
var _ reconcile.Reconciler = &PortScanPolicyReconciler{}

//+kubebuilder:rbac:groups=policy.open-cluster-management.io,resources=portscanpolicies,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=policy.open-cluster-management.io,resources=portscanpolicies/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=policy.open-cluster-management.io,resources=portscanpolicies/finalizers,verbs=update

//+kubebuilder:rbac:groups=core,resources=pods;services,verbs=get;list;watch
//+kubebuilder:rbac:groups=route.openshift.io,resources=routes,verbs=get;list;watch

//+kubebuilder:rbac:groups=core,resources=namespaces,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile schedules scans based on the Policy's spec. When the spec is
// updated the scan will be re-scheduled, but adjusting the status on its own
// will not trigger a reconciliation. If the Policy is deleted, the scan is
// de-activated (cancelling it if it's in progress)
func (r *PortScanPolicyReconciler) Reconcile(
	ctx context.Context, req ctrl.Request,
) (ctrl.Result, error) {
	reqLog := log.WithValues("PolicyNamespace", req.Namespace, "PolicyName", req.Name)
	reqLog.Info("Reconciling PortScanPolicy")

	// Fetch the PortScanPolicy instance
	psp := &policyv1alpha1.PortScanPolicy{}
	if err := r.Get(ctx, req.NamespacedName, psp); err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Cancel the scan if it's running.
			activeScansMux.Lock()
			defer activeScansMux.Unlock()

			cancel, found := activeScans[req.NamespacedName.String()]
			if found {
				cancel()
				delete(activeScans, req.NamespacedName.String())
			}

			reqLog.Info("PortScanPolicy resource not found - must have been deleted.",
				"ScanFoundAndCancelled", found)

			// Return and don't requeue
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request.
		reqLog.Error(err, "Failed to get PortScanPolicy")
		return ctrl.Result{}, err
	}

	activeScansMux.Lock()
	defer activeScansMux.Unlock()

	if cancel, found := activeScans[req.NamespacedName.String()]; found {
		reqLog.Info("Cancelling running scan before starting a new one")
		cancel()
	}

	// This is the parent context for the periodic scans - it will be re-used
	// until the Policy changes, which cancels this context.
	repeatingCtx, cancel := context.WithCancel(context.Background())
	activeScans[req.NamespacedName.String()] = cancel

	reqLog.Info("Starting new scan")
	go r.runScanSet(repeatingCtx, psp)

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *PortScanPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named(ControllerName).
		For(&policyv1alpha1.PortScanPolicy{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}). // only reconcile on spec updates
		Complete(r)
}
