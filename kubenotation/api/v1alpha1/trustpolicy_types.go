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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:scope=Cluster

// TrustPolicy defines a Notary trust policy document as specified here:
// https://notaryproject.dev/docs/concepts/trust-store-trust-policy-specification/#trust-policy
type TrustPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec contains the desired trust policy
	Spec TrustDocument `json:"spec"`
}

type TrustDocument struct {
	// Version of the policy document
	// +kubebuilder:default := "1.0"
	// +kubebuilder:validation:Enum="1.0"
	Version string `json:"version"`

	// TrustPolicies include each policy statement
	TrustPolicies []TrustPolicyStatement `json:"trustPolicies"`
}

// TrustPolicyStatement represents a policy statement in the policy document
type TrustPolicyStatement struct {
	// Name of the policy statement
	Name string `json:"name"`

	// RegistryScopes that this policy statement affects
	RegistryScopes []string `json:"registryScopes"`

	// SignatureVerification setting for this policy statement
	SignatureVerification SignatureVerification `json:"signatureVerification"`

	// TrustStores this policy statement uses
	TrustStores []string `json:"trustStores,omitempty"`

	// TrustedIdentities this policy statement pins
	TrustedIdentities []string `json:"trustedIdentities,omitempty"`
}

// SignatureVerification represents verification configuration in a trust policy
type SignatureVerification struct {
	// VerificationLevel specifies the desired signature verification level
	VerificationLevel VerificationLevel `json:"level"`

	// Override is an optional map of verification overrides
	// +kubebuilder:validation:Optional
	Override map[ValidationType]ValidationAction `json:"override,omitempty"`
}

// +kubebuilder:validation:Enum=strict;permissive;audit;skip
type VerificationLevel string

// +kubebuilder:validation:Enum=integrity;authenticity;authenticTimestamp;expiry;revocation
type ValidationType string

// +kubebuilder:validation:Enum=enforce;log;skip
type ValidationAction string

//+kubebuilder:object:root=true

// TrustPolicyList contains a list of TrustPolicy
type TrustPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TrustPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&TrustPolicy{}, &TrustPolicyList{})
}
