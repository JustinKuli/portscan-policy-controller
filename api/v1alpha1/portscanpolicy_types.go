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

//+kubebuilder:validation:Optional
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PortScanPolicySpec defines the desired state of PortScanPolicy
type PortScanPolicySpec struct {
	Severity          Severity          `json:"severity,omitempty"`
	RemediationAction RemediationAction `json:"remediationAction,omitempty"`
	NamespaceSelector NamespaceSelector `json:"namespaceSelector,omitempty"`

	//+kubebuilder:validation:UniqueIems=true
	//+kubebuilder:validation:MinItems=1
	//+kubebuilder:validation:Required
	ScanTargets []ScanTarget `json:"scanTargets"`

	//+kubebuilder:validation:UniqueIems=true
	//+kubebuilder:validation:MinItems=1
	//+kubebuilder:validation:Required
	Rules []Rule `json:"rules"`

	//+kubebuilder:default={compliant:"1h",noncompliant:"1h"}
	ScanInterval ScanInterval `json:"scanInterval"`

	//+kubebuilder:default=ListedOnly
	PortDiscovery PortDiscoveryOption `json:"portDiscovery"`
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

//+kubebuilder:validation:Enum=pods;routes;services
type ScanTarget string

const (
	ScanPods     ScanTarget = "pods"
	ScanRoutes   ScanTarget = "routes"
	ScanServices ScanTarget = "services"
)

type Rule struct {
	//+kubebuilder:validation:Enum=MinimumTLSVersion;MinimumCipherGrade;NoPort
	RuleName string `json:"name"`
	Value    string `json:"value,omitempty"`
}

type ScanInterval struct {
	//+kubebuilder:validation:Pattern=`^(?:(?:(?:[0-9]+(?:.[0-9])?)(?:h|m|s|(?:ms)|(?:us)|(?:ns)))|never)+$`
	Compliant string `json:"compliant,omitempty"`
	//+kubebuilder:validation:Pattern=`^(?:(?:(?:[0-9]+(?:.[0-9])?)(?:h|m|s|(?:ms)|(?:us)|(?:ns)))|never)+$`
	NonCompliant string `json:"noncompliant,omitempty"`
}

//+kubebuilder:validation:Pattern=`^(ListedOnly|Top([\d]+)|ListedAndTop([\d]+))$`
type PortDiscoveryOption string

const PortDiscoveryRegex string = `^(ListedOnly|Top([\d]+)|ListedAndTop([\d]+))$`

// END OF SPEC FIELDS

// PortScanPolicyStatus defines the observed state of PortScanPolicy
type PortScanPolicyStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// PortScanPolicy is the Schema for the portscanpolicies API
type PortScanPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PortScanPolicySpec   `json:"spec,omitempty"`
	Status PortScanPolicyStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// PortScanPolicyList contains a list of PortScanPolicy
type PortScanPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PortScanPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PortScanPolicy{}, &PortScanPolicyList{})
}
