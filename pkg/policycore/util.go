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

package policycore

import (
	"context"
	"path/filepath"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

//+kubebuilder:rbac:groups=core,resources=namespaces,verbs=get;list;watch

// GetNamespaces fetches all namespaces in the cluster and returns a list of the
// namespaces that match the NamespaceSelector.
func (sel NamespaceSelector) GetNamespaces(ctx context.Context, r client.Reader) ([]string, error) {
	matchingNamespaces := make([]string, 0)

	namespaceList := &corev1.NamespaceList{}
	if err := r.List(ctx, namespaceList); err != nil {
		return matchingNamespaces, err
	}

	namespaces := make([]string, len(namespaceList.Items))
	for i, ns := range namespaceList.Items {
		namespaces[i] = ns.GetName()
	}

	return sel.matches(namespaces)
}

// matches filters a slice of strings, and returns ones that match the selector
func (sel NamespaceSelector) matches(namespaces []string) ([]string, error) {
	matchingNamespaces := make([]string, 0)

	for _, namespace := range namespaces {
		include := false
		for _, includePattern := range sel.Include {
			var err error
			include, err = filepath.Match(string(includePattern), namespace)
			if err != nil { // The only possible returned error is ErrBadPattern, when pattern is malformed.
				return matchingNamespaces, err
			}
			if include {
				break
			}
		}
		if !include {
			continue
		}

		exclude := false
		for _, excludePattern := range sel.Exclude {
			var err error
			exclude, err = filepath.Match(string(excludePattern), namespace)
			if err != nil { // The only possible returned error is ErrBadPattern, when pattern is malformed.
				return matchingNamespaces, err
			}
			if exclude {
				break
			}
		}
		if exclude {
			continue
		}

		matchingNamespaces = append(matchingNamespaces, namespace)
	}

	return matchingNamespaces, nil
}

//+kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// RecordComplianceEvent creates an event on the "parent" policy of the given
// object (found through ownerReferences, which is set by the policy framework)
// which can be recognized by the policy framework to update the parent policy's
// status. This is the way that compliance information gets sent to the hub.
// The provided message will be prepended with "Compliant; " or "NonCompliant; "
// as required by the policy framework.
func RecordComplianceEvent(r record.EventRecorder, policy ObjectWithCompliance, msg string) {
	if len(policy.GetOwnerReferences()) != 0 {
		ownerRef := policy.GetOwnerReferences()[0]
		parentPolicy := &ParentPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      ownerRef.Name,
				Namespace: policy.GetNamespace(), // K8s ensures that owning objects are in the same namespace
				UID:       ownerRef.UID,
			},
			TypeMeta: metav1.TypeMeta{
				Kind:       ownerRef.Kind,
				APIVersion: ownerRef.APIVersion,
			},
		}

		eventType := "Normal"
		msgPrefix := "Compliant; "
		if policy.GetComplianceState() == NonCompliant {
			eventType = "Warning"
			msgPrefix = "NonCompliant; "
		}

		reason := "policy: " + policy.GetNamespace() + "/" + policy.GetName()

		r.Event(parentPolicy, eventType, reason, msgPrefix+msg)
	}
}
