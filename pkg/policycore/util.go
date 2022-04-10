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
	"sigs.k8s.io/controller-runtime/pkg/client"
)

//+kubebuilder:rbac:groups=core,resources=namespaces,verbs=get;list;watch

// GetNamespaces lists all namespaces in the cluster and returns a list of the
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
