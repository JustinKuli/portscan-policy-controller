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

//+kubebuilder:object:generate=true
package policycore

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type PolicyCoreSpec struct {
	Severity          Severity          `json:"severity,omitempty"`
	RemediationAction RemediationAction `json:"remediationAction,omitempty"`
	NamespaceSelector NamespaceSelector `json:"namespaceSelector,omitempty"`
}

//+kubebuilder:validation:Enum=low;medium;high;critical
type Severity string

const (
	LowSeverity      Severity = "low"
	MediumSeverity   Severity = "medium"
	HighSeverity     Severity = "high"
	CriticalSeverity Severity = "critical"
)

//+kubebuilder:validation:Enum=inform;enforce
type RemediationAction string

const (
	Inform  RemediationAction = "inform"
	Enforce RemediationAction = "enforce"
)

//+kubebuilder:validation:Required
type NamespaceSelector struct {
	Include []NonEmptyString `json:"include,omitempty"`
	Exclude []NonEmptyString `json:"exclude,omitempty"`
}

//+kubebuilder:validation:MinLength=1
type NonEmptyString string

type PolicyCoreStatus struct {
	ComplianceState ComplianceState `json:"compliant,omitempty"`
}

type ComplianceState string

const (
	// Compliant is an ComplianceState
	Compliant ComplianceState = "Compliant"

	// NonCompliant is an ComplianceState
	NonCompliant ComplianceState = "NonCompliant"

	// UnknownCompliancy is an ComplianceState
	UnknownCompliancy ComplianceState = "UnknownCompliancy"
)

//+kubebuilder:object:root=true

// ParentPolicy is a basic Kubernetes object. It is a simplified stand-in for the actual Policy
// type so that events can be triggered as required by the policy framework without importing the
// full Policy API.
type ParentPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
}
