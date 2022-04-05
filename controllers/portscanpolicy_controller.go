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
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	policyv1alpha1 "github.com/JustinKuli/portscan-policy-controller/api/v1alpha1"
	"github.com/JustinKuli/portscan-policy-controller/pkg/policycore"
	"github.com/JustinKuli/portscan-policy-controller/pkg/scan"
	"github.com/JustinKuli/portscan-policy-controller/pkg/scan/scriptout"
)

const (
	ControllerName = "port-scan-policy-controller"
	ScanTimeout    = 20 * time.Minute
)

var (
	log             = ctrl.Log.WithName(ControllerName)
	runningScans    = make(map[string]context.CancelFunc)
	runningScansMux = sync.Mutex{}
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

func (r *PortScanPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	reqLog := log.WithValues("PolicyNamespace", req.Namespace, "PolicyName", req.Name)
	reqLog.Info("Reconciling PortScanPolicy")

	// Fetch the PortScanPolicy instance
	psp := &policyv1alpha1.PortScanPolicy{}
	if err := r.Get(ctx, req.NamespacedName, psp); err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Cancel the scan if it's running
			runningScansMux.Lock()
			defer runningScansMux.Unlock()

			cancel, found := runningScans[req.NamespacedName.String()]
			if found {
				cancel()
				delete(runningScans, req.NamespacedName.String())
			}

			reqLog.Info("PortScanPolicy resource not found - must have been deleted.", "ScanFoundAndCancelled", found)

			// Return and don't requeue
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request.
		reqLog.Error(err, "Failed to get PortScanPolicy")
		return ctrl.Result{}, err
	}

	runningScansMux.Lock()
	defer runningScansMux.Unlock()

	if cancel, found := runningScans[req.NamespacedName.String()]; found {
		reqLog.Info("Cancelling running scan before starting a new one")
		cancel()
	}

	// This is the parent context for the periodic scans - it will be re-used until the Policy
	// changes, which cancels this context.
	repeatingCtx, cancel := context.WithCancel(context.Background())
	runningScans[req.NamespacedName.String()] = cancel

	reqLog.Info("Starting new scan")
	go r.runScan(repeatingCtx, psp)

	return ctrl.Result{}, nil
}

func (r *PortScanPolicyReconciler) runScan(ctx context.Context, psp *policyv1alpha1.PortScanPolicy) {
	scanLog := log.WithValues("PolicyNamespace", psp.GetNamespace(), "PolicyName", psp.GetName())

	// This limits the scan's possible duration - both the nmap command itself, and the processing.
	scanCtx, scanCancel := context.WithTimeout(ctx, ScanTimeout)
	defer scanCancel()

	scanLog.V(1).Info("Determining covered namespaces")
	coveredNamespaces, err := psp.Spec.NamespaceSelector.GetNamespaces(scanCtx, r)
	if err != nil {
		scanLog.Error(err, "Failed to get namespaces using namespace selector",
			"NamespaceSelector", psp.Spec.NamespaceSelector)
		// TODO: Handle creating a violation here (or not, if context was cancelled/expired)
		return
	}
	scanLog.V(2).Info("Determined covered namespaces", "coveredNamespaces", coveredNamespaces)

	scanLog.V(1).Info("Determining addresses of scan targets")
	scanTargets := make(map[string]scanTarget, 0)
	for _, ns := range coveredNamespaces {
		targets, err := r.getTargets(scanCtx, ns, psp.Spec.ScanTargetKinds)
		if err != nil {
			// TODO: Handle creating a violation here (or not, if context was cancelled/expired)
			// TODO: Ignore(?) 'unknown ScanTargetKind' errors
			return
		}
		for ip, target := range targets {
			scanTargets[ip] = target
		}
	}
	scanLog.V(2).Info("Determined scan target details", "scanTargets", scanTargets)

	scanLog.Info("Starting scans", "ScanCount", len(psp.Spec.PortDiscovery))
	reports, err := getReports(scanCtx, scanTargets, psp.Spec.PortDiscovery)
	if err != nil {
		// TODO: Handle error
		return
	}

	scanLog.Info("Got reports, determining compliance status", "reportsCount", len(reports))
	violations := make([]policyv1alpha1.PortScanViolation, 0)

	for _, rule := range psp.Spec.Rules {
		for _, report := range reports {
			vs, err := getViolations(rule, report, scanTargets)
			if err != nil {
				// TODO: Handle error
				fmt.Println("Uh-oh error 160")
			}
			violations = append(violations, vs...)

			// TODO: check if the scanCtx context was cancelled ctx
		}
	}

	scanLog.Info("Got compliance status", "violationsCount", len(violations))
	sort.Slice(violations, func(i, j int) bool {
		vi, vj := violations[i], violations[j]
		return vi.Kind+vi.Name+vi.Namespace+vi.Message < vj.Kind+vj.Name+vj.Namespace+vj.Message
	}) // sort for more consistent ordering between scans

	psp.Status = policyv1alpha1.PortScanPolicyStatus{
		LastScanCompletion: time.Now().Format(time.RFC3339),
		Violations:         violations,
	}
	var msg, scanInterval string
	if len(violations) == 0 {
		psp.Status.ComplianceState = policycore.Compliant
		// The "Compliant" part is required by the status sync, the rest is just conventional/informational
		msg = "Compliant; notification - port scan completed and found no violations"
		scanInterval = psp.Spec.ScanInterval.Compliant
	} else {
		psp.Status.ComplianceState = policycore.NonCompliant
		msg = "NonCompliant; violation - port scan completed but found "
		if len(violations) == 1 {
			v := violations[0]
			msg += fmt.Sprintf("one violation: %v %v in namespace %v has violation '%v'",
				v.Kind, v.Name, v.Namespace, v.Message)
		} else {
			msg += "multiple violations"
		}
		scanInterval = psp.Spec.ScanInterval.NonCompliant
	}

	r.recordComplianceEventOnParent(psp, msg)
	if err := r.Status().Update(scanCtx, psp); err != nil {
		// TODO: Handle error
		fmt.Println("Uh-oh, error 205")
	}

	if scanInterval == "never" {
		// Don't need to schedule another scan
		return
	}

	sleepDuration, err := time.ParseDuration(scanInterval)
	if err != nil {
		// TODO: Handle error
		fmt.Println("Uh-oh, error 218")
	}

	sleepTimer := time.NewTimer(sleepDuration)

	select {
	case <-sleepTimer.C:
		go r.runScan(ctx, psp)
	case <-ctx.Done():
		// stop the timer, and drain its channel if necessary
		if !sleepTimer.Stop() {
			<-sleepTimer.C
		}
	}
}

type scanTarget struct {
	kind      string
	namespace string
	name      string
	ports     []int
}

// blank assignment to verify that scanTarget implements fmt.Stringer
var _ fmt.Stringer = scanTarget{}

func (s scanTarget) String() string {
	return s.kind + ":" + s.namespace + "/" + s.name
}

func (r *PortScanPolicyReconciler) getTargets(ctx context.Context, namespace string, kinds []policyv1alpha1.ScanTargetKind) (map[string]scanTarget, error) {
	scanTargets := make(map[string]scanTarget)
	var kindErr error

	for _, scanKind := range kinds {
		switch scanKind {
		case policyv1alpha1.ScanPods:
			// TODO: implement
		case policyv1alpha1.ScanRoutes:
			// TODO: implement
		case policyv1alpha1.ScanServices:
			svcList := &corev1.ServiceList{}
			if err := r.List(ctx, svcList, &client.ListOptions{Namespace: namespace}); err != nil {
				return scanTargets, err
			}

			for _, svc := range svcList.Items {
				ports := make([]int, len(svc.Spec.Ports))
				for i, p := range svc.Spec.Ports {
					ports[i] = int(p.Port)
				}
				for _, ip := range svc.Spec.ClusterIPs {
					scanTargets[ip] = scanTarget{
						kind:      "service[clusterIP]",
						namespace: namespace,
						name:      svc.GetName(),
						ports:     ports,
					}
				}
				for _, ip := range svc.Spec.ExternalIPs {
					scanTargets[ip] = scanTarget{
						kind:      "service[externalIP]",
						namespace: namespace,
						name:      svc.GetName(),
						ports:     ports,
					}
				}
			}
		default:
			// TODO: improve this error, maybe with a custom type so it can be handled specially?
			kindErr = fmt.Errorf("unknown ScanTargetKind: '%v'", scanKind)
		}
	}

	return scanTargets, kindErr
}

func flattenPortsAndIPs(targets map[string]scanTarget) (ports []int, ips []string) {
	portSet := make(map[int]bool)
	ips = make([]string, 0, len(targets))
	for ip, t := range targets {
		ips = append(ips, ip)
		for _, p := range t.ports {
			portSet[p] = true
		}
	}

	ports = make([]int, 0, len(portSet))
	for p := range portSet {
		ports = append(ports, p)
	}

	return ports, ips
}

func getReports(ctx context.Context, scanTargets map[string]scanTarget, portOpts []policyv1alpha1.PortDiscoveryOption) ([]scriptout.NMapRun, error) {
	k8sListedPorts, ips := flattenPortsAndIPs(scanTargets)

	g, gctx := errgroup.WithContext(ctx)
	reportCh := make(chan scriptout.NMapRun)

	for _, portOpt := range portOpts {
		runner := scan.SSLEnum(ips)

		switch portOpt.Type {
		case policyv1alpha1.PortTypeK8sListed:
			runner = runner.WithSpecificPorts(k8sListedPorts)
		case policyv1alpha1.PortTypeTop:
			topPorts, err := strconv.Atoi(portOpt.Value)
			if err != nil {
				// TODO: Handle this error
				fmt.Println("Uh-oh error 294")
			}

			runner = runner.WithTopNPorts(topPorts)
		case policyv1alpha1.PortTypeSpecific:
			portStrs := strings.Split(portOpt.Value, ",")
			ports := make([]int, len(portStrs))
			for i, p := range portStrs {
				port, err := strconv.Atoi(p)
				if err != nil {
					// TODO: Handle this error
					fmt.Println("Uh-oh error 305")
				}
				ports[i] = port
			}

			runner = runner.WithSpecificPorts(ports)
		default:
			// TODO: Handle this as an error?
		}

		g.Go(func() error {
			out, err := runner.Run(gctx)
			if err != nil {
				return err
			}
			select {
			case reportCh <- out:
			case <-gctx.Done():
				return gctx.Err()
			}
			return nil
		})
	}

	go func() {
		g.Wait()
		close(reportCh)
	}()

	reports := make([]scriptout.NMapRun, 0, len(portOpts))
	for r := range reportCh {
		reports = append(reports, r)
	}

	return reports, g.Wait()
}

func getViolations(rule policyv1alpha1.Rule, report scriptout.NMapRun, scanTargets map[string]scanTarget) ([]policyv1alpha1.PortScanViolation, error) {
	switch rule.Name {
	case policyv1alpha1.RuleMinimumCipherGrade:
		if len(rule.Value) != 1 {
			return nil, fmt.Errorf("invalid MinimumCipherGrade value under name: '%v'", rule.Name)
		}

		requiredGrade := []rune(rule.Value)[0]

		worstGrade, err := report.LeastStrengthAll()
		if err != nil {
			return nil, err
		}

		if worstGrade <= requiredGrade {
			// All good!
			return nil, nil
		}

		violations := make([]policyv1alpha1.PortScanViolation, 0)
		for _, cipher := range report.GetFlatCiphers() {
			if len(cipher.CipherInfo.Strength) < 1 {
				return violations, fmt.Errorf("found invalid cipher strength under %v/%v/%v/%v in report",
					cipher.HostAddr, cipher.PortID, cipher.TLSVersion, cipher.CipherInfo.Name)
			}

			cipherGrade := []rune(cipher.CipherInfo.Strength)[0]
			if cipherGrade <= requiredGrade {
				// This cipher was good
				continue
			}

			matchedTarget, found := scanTargets[cipher.HostAddr]
			if !found {
				return violations, fmt.Errorf("unable to match target for %v in report", cipher.HostAddr)
			}

			violations = append(violations, policyv1alpha1.PortScanViolation{
				Kind:      matchedTarget.kind,
				Name:      matchedTarget.name,
				Namespace: matchedTarget.namespace,
				Message: fmt.Sprintf("Cipher '%v' on %v:%v has strength '%v', needs '%c' or better",
					cipher.CipherInfo.Name, cipher.HostAddr, cipher.PortID, cipher.CipherInfo.Strength, requiredGrade),
			})
		}

		return violations, nil

	case policyv1alpha1.RuleMinimumTLSVersion:
		// TODO: implement
		return nil, nil

	case policyv1alpha1.RuleNoPort:
		// TODO: implement
		return nil, nil

	default:
		return nil, fmt.Errorf("unknown RuleName: '%v'", rule)
	}
}

func (r *PortScanPolicyReconciler) recordComplianceEventOnParent(psp *policyv1alpha1.PortScanPolicy, msg string) {
	if len(psp.OwnerReferences) != 0 {
		owner := psp.OwnerReferences[0]
		parentPolicy := &policycore.ParentPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      owner.Name,
				Namespace: psp.GetNamespace(), // Owning objects must be in the same namespace
				UID:       owner.UID,
			},
			TypeMeta: metav1.TypeMeta{
				Kind:       owner.Kind,
				APIVersion: owner.APIVersion,
			},
		}

		eventType := "Normal"
		if psp.Status.ComplianceState == policycore.NonCompliant {
			eventType = "Warning"
		}

		reason := "policy: " + psp.GetNamespace() + "/" + psp.GetName()

		r.Recorder.Event(parentPolicy, eventType, reason, msg)
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *PortScanPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named(ControllerName).
		For(&policyv1alpha1.PortScanPolicy{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}). // only reconcile on spec updates
		Complete(r)
}
