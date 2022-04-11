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
	"github.com/JustinKuli/portscan-policy-controller/pkg/policycore"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PortScanPolicySpec defines the desired state of PortScanPolicy
type PortScanPolicySpec struct {
	policycore.PolicyCoreSpec `json:",inline"`

	//+kubebuilder:validation:UniqueIems=true
	//+kubebuilder:validation:MinItems=1
	//+kubebuilder:validation:Required
	ScanTargetKinds []ScanTargetKind `json:"scanTargetKinds"`

	//+kubebuilder:validation:UniqueIems=true
	//+kubebuilder:validation:MinItems=1
	//+kubebuilder:validation:Required
	Rules []Rule `json:"rules"`

	//+kubebuilder:default={compliant:"1h",noncompliant:"1h"}
	ScanInterval ScanInterval `json:"scanInterval"`

	//+kubebuilder:default={{type:"K8sListed"}}
	PortDiscovery []PortDiscoveryOption `json:"portDiscovery"`
}

//+kubebuilder:validation:Enum=pods;routes;services
type ScanTargetKind string

const (
	ScanPods     ScanTargetKind = "pods"
	ScanRoutes   ScanTargetKind = "routes"
	ScanServices ScanTargetKind = "services"
)

type Rule struct {
	//+kubebuilder:validation:Required
	Name  RuleName `json:"name"`
	Value string   `json:"value,omitempty"`
}

//+kubebuilder:validation:Enum=MinimumTLSVersion;MinimumCipherGrade;NoPort
type RuleName string

const (
	RuleMinimumTLSVersion  RuleName = "MinimumTLSVersion"
	RuleMinimumCipherGrade RuleName = "MinimumCipherGrade"
	RuleNoPort             RuleName = "NoPort"
)

type ScanInterval struct {
	//+kubebuilder:validation:Pattern=`^(?:(?:(?:[0-9]+(?:.[0-9])?)(?:h|m|s|(?:ms)|(?:us)|(?:ns)))|never)+$`
	Compliant string `json:"compliant,omitempty"`
	//+kubebuilder:validation:Pattern=`^(?:(?:(?:[0-9]+(?:.[0-9])?)(?:h|m|s|(?:ms)|(?:us)|(?:ns)))|never)+$`
	NonCompliant string `json:"noncompliant,omitempty"`
}

type PortDiscoveryOption struct {
	//+kubebuilder:validation:Required
	Type  PortType `json:"type"`
	Value string   `json:"value,omitempty"`
}

//+kubebuilder:validation:Enum=K8sListed;Top;Specific
type PortType string

const (
	PortTypeK8sListed PortType = "K8sListed"
	PortTypeTop       PortType = "Top"
	PortTypeSpecific  PortType = "Specific"
)

// PortScanPolicyStatus defines the observed state of PortScanPolicy
type PortScanPolicyStatus struct {
	policycore.PolicyCoreStatus `json:",inline"`

	LastScanCompletion string `json:"lastScanCompletion,omitempty"`
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

func (p *PortScanPolicy) GetComplianceState() policycore.ComplianceState {
	return p.Status.ComplianceState
}

// blank assignment to verify that PortScanPolicy implements policycore.ObjectWithCompliance
var _ policycore.ObjectWithCompliance = &PortScanPolicy{}

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
