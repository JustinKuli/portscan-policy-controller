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
	"time"

	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	policyv1alpha1 "github.com/JustinKuli/portscan-policy-controller/api/v1alpha1"
	"github.com/JustinKuli/portscan-policy-controller/pkg/policycore"
	"github.com/JustinKuli/portscan-policy-controller/pkg/scan"
	"github.com/JustinKuli/portscan-policy-controller/pkg/scan/scriptout"
)

func (r *PortScanPolicyReconciler) runScanSet(
	ctx context.Context, psp *policyv1alpha1.PortScanPolicy,
) {
	scanLog := log.WithValues("PolicyNamespace", psp.GetNamespace(), "PolicyName", psp.GetName())

	// This limits the scanset's possible duration
	scanCtx, scanCancel := context.WithTimeout(ctx, ScanTimeout)
	defer scanCancel()

	scanLog.Info("Getting scan targets")
	scanTargets, err := getTargets(scanCtx, psp, r)
	if err != nil {
		// TODO: Check if ctx is expired - if not, create a violation.
		return
	}

	scanLog.Info("Starting scans", "ScanCount", len(psp.Spec.PortDiscovery))
	reports, err := getReports(scanCtx, scanTargets, psp.Spec.PortDiscovery)
	if err != nil {
		// TODO: Check if ctx is expired - if not, create a violation.
		return
	}

	scanLog.Info("Got reports, determining compliance status", "reportsCount", len(reports))
	violations, err := getViolations(psp.Spec.Rules, reports, scanTargets)
	if err != nil {
		// TODO: An error here would *not* be from an expired ctx - just report as a violation
		return
	}
	scanLog.Info("Got compliance status", "violationsCount", len(violations))

	psp.Status = policyv1alpha1.PortScanPolicyStatus{
		LastScanCompletion: time.Now().Format(time.RFC3339),
		Violations:         violations,
	}
	var msg, scanInterval string
	if len(violations) == 0 {
		psp.Status.ComplianceState = policycore.Compliant
		// The "Compliant" part is required by the status sync,
		// the rest is just conventional/informational
		msg = "Compliant; notification - port scan completed and found no violations"
		scanInterval = psp.Spec.ScanInterval.Compliant
	} else {
		psp.Status.ComplianceState = policycore.NonCompliant
		msg = "NonCompliant; violation - port scan completed but found "
		if len(violations) == 1 {
			v := violations[0]
			msg += fmt.Sprintf("that %v %v in namespace %v has violation '%v'",
				v.Kind, v.Name, v.Namespace, v.Message)
		} else {
			msg += "multiple violations"
		}
		scanInterval = psp.Spec.ScanInterval.NonCompliant
	}

	r.recordComplianceEventOnParent(psp, msg)
	if err := r.Status().Update(scanCtx, psp); err != nil {
		// TODO: Check if ctx is expired ... if not, retry?
		fmt.Println("Uh-oh, error 205")
	}

	if scanInterval == "never" {
		// Don't need to schedule another scan
		return
	}

	sleepDuration, err := time.ParseDuration(scanInterval)
	if err != nil {
		// TODO: Handle error ... log and use a default?
		fmt.Println("Uh-oh, error 218")
	}

	sleepTimer := time.NewTimer(sleepDuration)

	select {
	case <-sleepTimer.C:
		go r.runScanSet(ctx, psp)
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

// getTargets finds targets of the Policy by using the NamespaceSelector and
// ScanTargetKinds. The returned value is a map keyed by IP in order to easily
// link violations from the nmap report to what k8s object was scanned.
func getTargets(
	ctx context.Context, psp *policyv1alpha1.PortScanPolicy, r client.Reader,
) (map[string]scanTarget, error) {
	scanLog := log.WithValues("PolicyNamespace", psp.GetNamespace(), "PolicyName", psp.GetName())

	scanLog.V(1).Info("Determining selected namespaces")
	coveredNamespaces, err := psp.Spec.NamespaceSelector.GetNamespaces(ctx, r)
	if err != nil {
		return nil, fmt.Errorf("unable to determine selected namespaces: %w", err)
	}

	scanLog.V(1).Info("Determining addresses of scan targets")
	scanTargets := make(map[string]scanTarget, 0)
	for _, ns := range coveredNamespaces {
		for _, scanKind := range psp.Spec.ScanTargetKinds {
			switch scanKind {
			case policyv1alpha1.ScanPods:
				// TODO: implement
			case policyv1alpha1.ScanRoutes:
				// TODO: implement
			case policyv1alpha1.ScanServices:
				addTargets, err := svcTargets(ctx, r, ns)
				if err != nil {
					return nil, err
				}

				for ip, target := range addTargets {
					scanTargets[ip] = target
				}
			default:
				// The kubernetes spec validation *should* prevent this from occurring.
				scanLog.Info("Unknown option, skipping this kind", "ScanTargetKind", scanKind)
			}
		}
	}
	scanLog.V(2).Info("Determined scan target details", "scanTargets", scanTargets)

	return nil, nil
}

func svcTargets(ctx context.Context, r client.Reader, ns string) (map[string]scanTarget, error) {
	targets := make(map[string]scanTarget)

	svcList := &corev1.ServiceList{}
	if err := r.List(ctx, svcList, &client.ListOptions{Namespace: ns}); err != nil {
		return nil, err
	}

	for _, svc := range svcList.Items {
		ports := make([]int, len(svc.Spec.Ports))
		for i, p := range svc.Spec.Ports {
			ports[i] = int(p.Port)
		}
		for _, ip := range svc.Spec.ClusterIPs {
			targets[ip] = scanTarget{
				kind:      "service[clusterIP]",
				namespace: ns,
				name:      svc.GetName(),
				ports:     ports,
			}
		}
		for _, ip := range svc.Spec.ExternalIPs {
			targets[ip] = scanTarget{
				kind:      "service[externalIP]",
				namespace: ns,
				name:      svc.GetName(),
				ports:     ports,
			}
		}
	}

	return targets, nil
}

// getReports executes an nmap command for each PortDiscoveryOption, and gathers
// the reports created. The scans are run concurrently. Any invalid
// PortDiscoveryOption will trigger an error, cancel the scans, and no reports
// will be returned.
func getReports(
	ctx context.Context,
	scanTargets map[string]scanTarget,
	portOpts []policyv1alpha1.PortDiscoveryOption,
) ([]scriptout.NMapRun, error) {
	k8sListedPorts, ips := flattenPortsAndIPs(scanTargets)

	pipelineCtx, cancel := context.WithCancel(ctx)
	defer cancel() // early error returns will cancel any other active work

	g, groupCtx := errgroup.WithContext(pipelineCtx)
	reportCh := make(chan scriptout.NMapRun)

	for _, portOpt := range portOpts {
		runner := scan.SSLEnum(ips)

		switch portOpt.Type {
		case policyv1alpha1.PortTypeK8sListed:
			// Implementation note: this scan does not run the specific ports each address is
			// associated with - it runs on *all* ports *any* of the addresses are associated with.
			// That covers the the specific ports on each address, but in general includes extras.
			runner = runner.WithSpecificPorts(k8sListedPorts)

		case policyv1alpha1.PortTypeTop:
			// Implementation note: the "top ports" that nmap uses are taken from a configuration
			// file in the container. That config file could be adjusted to add more k8s-specific
			// ports if necessary, or at least adjust the "probablility" weights accordingly.
			topPorts, err := strconv.Atoi(portOpt.Value)
			if err != nil {
				return nil, fmt.Errorf("invalid 'Top' PortType value: '%v': %w",
					portOpt.Value, err)
			}

			runner = runner.WithTopNPorts(topPorts)
		case policyv1alpha1.PortTypeSpecific:
			// Implementation note: each individual port must be listed - no ranges are allowed,
			// unlike the underlying nmap option. As a special case, "-" is allowed, which tells
			// nmap to scan *all* ports.
			if portOpt.Value == "-" {
				runner = runner.WithAllPorts()
			} else {
				portStrs := strings.Split(portOpt.Value, ",")
				ports := make([]int, len(portStrs))
				for i, p := range portStrs {
					port, err := strconv.Atoi(p)
					if err != nil {
						return nil, fmt.Errorf("invalid 'Specific' PortType value: '%v': %w",
							portOpt.Value, err)
					}
					ports[i] = port
				}

				runner = runner.WithSpecificPorts(ports)
			}

		default:
			// The kubernetes spec validation *should* prevent this from occurring.
			return nil, fmt.Errorf("unknown PortDiscoveryOption type '%v'", portOpt.Type)
		}

		g.Go(func() error {
			out, err := runner.Run(groupCtx)
			if err != nil {
				return err
			}
			select {
			case reportCh <- out:
			case <-groupCtx.Done():
				return groupCtx.Err()
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

// flattenPortsAndIPs converts the map of targets into lists of ports and IPs.
// The lists will not have duplicate entries.
func flattenPortsAndIPs(targets map[string]scanTarget) (ports []int, ips []string) {
	portSet := make(map[int]struct{})
	ips = make([]string, 0, len(targets))
	for ip, t := range targets {
		ips = append(ips, ip)
		for _, p := range t.ports {
			portSet[p] = struct{}{}
		}
	}

	ports = make([]int, 0, len(portSet))
	for p := range portSet {
		ports = append(ports, p)
	}

	return ports, ips
}

// getViolations gathers all violations from all of the specified rules in all
// of the reports. It uses the scanTargets to map violations in the report to
// the kind/namespace/name of the scanned k8s objects. The returned violations
// are sorted. It will return an error if a rule is invalid, or if the report
// can't be fully analyzed to find the violations.
func getViolations(
	rules []policyv1alpha1.Rule,
	reports []scriptout.NMapRun,
	scanTargets map[string]scanTarget,
) ([]policyv1alpha1.PortScanViolation, error) {
	violations := make([]policyv1alpha1.PortScanViolation, 0)

	for _, report := range reports {
		for _, rule := range rules {
			switch rule.Name {
			case policyv1alpha1.RuleMinimumCipherGrade:
				addViolations, err := minimumCipherGradeViolations(rule.Value, report, scanTargets)
				if err != nil {
					return nil, err
				}

				violations = append(violations, addViolations...)

			case policyv1alpha1.RuleMinimumTLSVersion:
				// TODO: implement

			case policyv1alpha1.RuleNoPort:
				// TODO: implement

			default:
				// The kubernetes spec validation *should* prevent this from occurring.
				return nil, fmt.Errorf("unknown RuleName: '%v'", rule.Name)
			}
		}
	}

	sort.Slice(violations, func(i, j int) bool {
		vi, vj := violations[i], violations[j]
		return vi.Kind+vi.Namespace+vi.Name+vi.Message < vj.Kind+vj.Namespace+vj.Name+vj.Message
	})

	return violations, nil
}

// minimumCipherGradeViolations analyzes the report and returns any ciphers that
// don't pass the minimum cipher grade. It will return an error if the nmap
// report didn't report a grade for any cipher, or if the input ruleValue is
// invalid. The violations will map back to kind/namespace/name in the
// scanTargets, when possible.
func minimumCipherGradeViolations(
	ruleValue string,
	report scriptout.NMapRun,
	scanTargets map[string]scanTarget,
) ([]policyv1alpha1.PortScanViolation, error) {
	if len(ruleValue) != 1 {
		return nil, fmt.Errorf("invalid 'MinimumCipherGrade' Rule value: '%v': "+
			"must be one character", ruleValue)
	}

	requiredGrade := []rune(ruleValue)[0]

	worstGrade, err := report.LeastStrengthAll()
	if err != nil {
		return nil, err
	}

	if worstGrade <= requiredGrade {
		// All good! (smaller rune value means earlier in the alphabet)
		return nil, nil
	}

	violations := make([]policyv1alpha1.PortScanViolation, 0)
	for _, cipher := range report.GetFlatCiphers() {
		if len(cipher.CipherInfo.Strength) < 1 {
			// This probably won't happen, but the nmap script is a bit of an unknown.
			// If it happens, we might not be able to trust anything else in the report,
			// so we'll throw the rest of the report away and report this as a violation.
			return nil, fmt.Errorf("found invalid cipher strength under %v/%v/%v/%v in report",
				cipher.HostAddr, cipher.PortID, cipher.TLSVersion, cipher.CipherInfo.Name)
		}

		cipherGrade := []rune(cipher.CipherInfo.Strength)[0]
		if cipherGrade <= requiredGrade {
			// This cipher was good (smaller rune value means earlier in the alphabet)
			continue
		}

		matchedTarget, found := scanTargets[cipher.HostAddr]
		if !found {
			// Unlikely, but the rest of the scan could still be good, so don't return an error.
			matchedTarget = scanTarget{kind: "unknown", namespace: "unknown", name: "unknown"}
		}

		violations = append(violations, policyv1alpha1.PortScanViolation{
			Kind:      matchedTarget.kind,
			Name:      matchedTarget.name,
			Namespace: matchedTarget.namespace,
			Message: fmt.Sprintf("Cipher '%v' on %v:%v has strength '%v', needs '%c' or better",
				cipher.CipherInfo.Name, cipher.HostAddr, cipher.PortID, cipher.CipherInfo.Strength,
				requiredGrade),
		})
	}

	return violations, nil
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
