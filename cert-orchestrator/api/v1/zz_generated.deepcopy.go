//go:build !ignore_autogenerated
// +build !ignore_autogenerated

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

// Code generated by controller-gen. DO NOT EDIT.

package v1

import (
	"github.com/AppViewX/appviewx-csi-provider/cert-orchestrator/api/v1/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AppViewXCASetting) DeepCopyInto(out *AppViewXCASetting) {
	*out = *in
	in.CAConnectorInfo.DeepCopyInto(&out.CAConnectorInfo)
	out.CertificateGroup = in.CertificateGroup
	if in.Secret != nil {
		in, out := &in.Secret, &out.Secret
		*out = new(NamespacedName)
		**out = **in
	}
	if in.Vault != nil {
		in, out := &in.Vault, &out.Vault
		*out = new(VaultConfiguration)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AppViewXCASetting.
func (in *AppViewXCASetting) DeepCopy() *AppViewXCASetting {
	if in == nil {
		return nil
	}
	out := new(AppViewXCASetting)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CACASetting) DeepCopyInto(out *CACASetting) {
	*out = *in
	if in.CRLDistributionPoints != nil {
		in, out := &in.CRLDistributionPoints, &out.CRLDistributionPoints
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.OCSPServers != nil {
		in, out := &in.OCSPServers, &out.OCSPServers
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CACASetting.
func (in *CACASetting) DeepCopy() *CACASetting {
	if in == nil {
		return nil
	}
	out := new(CACASetting)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CAConnectorInfo) DeepCopyInto(out *CAConnectorInfo) {
	*out = *in
	if in.ValidityUnit != nil {
		in, out := &in.ValidityUnit, &out.ValidityUnit
		*out = new(string)
		**out = **in
	}
	if in.ValidityUnitValue != nil {
		in, out := &in.ValidityUnitValue, &out.ValidityUnitValue
		*out = new(int)
		**out = **in
	}
	if in.VendorSpecificDetails != nil {
		in, out := &in.VendorSpecificDetails, &out.VendorSpecificDetails
		*out = new(string)
		**out = **in
	}
	if in.CertificateProfileName != nil {
		in, out := &in.CertificateProfileName, &out.CertificateProfileName
		*out = new(string)
		**out = **in
	}
	if in.IssuerLocation != nil {
		in, out := &in.IssuerLocation, &out.IssuerLocation
		*out = new(string)
		**out = **in
	}
	if in.IssuerName != nil {
		in, out := &in.IssuerName, &out.IssuerName
		*out = new(string)
		**out = **in
	}
	if in.Name != nil {
		in, out := &in.Name, &out.Name
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CAConnectorInfo.
func (in *CAConnectorInfo) DeepCopy() *CAConnectorInfo {
	if in == nil {
		return nil
	}
	out := new(CAConnectorInfo)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CASetting) DeepCopyInto(out *CASetting) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CASetting.
func (in *CASetting) DeepCopy() *CASetting {
	if in == nil {
		return nil
	}
	out := new(CASetting)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *CASetting) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CASettingCluster) DeepCopyInto(out *CASettingCluster) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	out.Status = in.Status
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CASettingCluster.
func (in *CASettingCluster) DeepCopy() *CASettingCluster {
	if in == nil {
		return nil
	}
	out := new(CASettingCluster)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *CASettingCluster) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CASettingClusterList) DeepCopyInto(out *CASettingClusterList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]CASettingCluster, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CASettingClusterList.
func (in *CASettingClusterList) DeepCopy() *CASettingClusterList {
	if in == nil {
		return nil
	}
	out := new(CASettingClusterList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *CASettingClusterList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CASettingClusterSpec) DeepCopyInto(out *CASettingClusterSpec) {
	*out = *in
	in.CASettingConfig.DeepCopyInto(&out.CASettingConfig)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CASettingClusterSpec.
func (in *CASettingClusterSpec) DeepCopy() *CASettingClusterSpec {
	if in == nil {
		return nil
	}
	out := new(CASettingClusterSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CASettingClusterStatus) DeepCopyInto(out *CASettingClusterStatus) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CASettingClusterStatus.
func (in *CASettingClusterStatus) DeepCopy() *CASettingClusterStatus {
	if in == nil {
		return nil
	}
	out := new(CASettingClusterStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CASettingConfig) DeepCopyInto(out *CASettingConfig) {
	*out = *in
	if in.CA != nil {
		in, out := &in.CA, &out.CA
		*out = new(CACASetting)
		(*in).DeepCopyInto(*out)
	}
	if in.Vault != nil {
		in, out := &in.Vault, &out.Vault
		*out = new(VaultCASetting)
		(*in).DeepCopyInto(*out)
	}
	if in.SelfSigned != nil {
		in, out := &in.SelfSigned, &out.SelfSigned
		*out = new(SelfSignedCASetting)
		(*in).DeepCopyInto(*out)
	}
	if in.AppViewX != nil {
		in, out := &in.AppViewX, &out.AppViewX
		*out = new(AppViewXCASetting)
		(*in).DeepCopyInto(*out)
	}
	if in.EST != nil {
		in, out := &in.EST, &out.EST
		*out = new(ESTSetting)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CASettingConfig.
func (in *CASettingConfig) DeepCopy() *CASettingConfig {
	if in == nil {
		return nil
	}
	out := new(CASettingConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CASettingList) DeepCopyInto(out *CASettingList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]CASetting, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CASettingList.
func (in *CASettingList) DeepCopy() *CASettingList {
	if in == nil {
		return nil
	}
	out := new(CASettingList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *CASettingList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CASettingSpec) DeepCopyInto(out *CASettingSpec) {
	*out = *in
	in.CASettingConfig.DeepCopyInto(&out.CASettingConfig)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CASettingSpec.
func (in *CASettingSpec) DeepCopy() *CASettingSpec {
	if in == nil {
		return nil
	}
	out := new(CASettingSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CASettingStatus) DeepCopyInto(out *CASettingStatus) {
	*out = *in
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]IssuerCondition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CASettingStatus.
func (in *CASettingStatus) DeepCopy() *CASettingStatus {
	if in == nil {
		return nil
	}
	out := new(CASettingStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Cert) DeepCopyInto(out *Cert) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Cert.
func (in *Cert) DeepCopy() *Cert {
	if in == nil {
		return nil
	}
	out := new(Cert)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *Cert) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CertList) DeepCopyInto(out *CertList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]Cert, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CertList.
func (in *CertList) DeepCopy() *CertList {
	if in == nil {
		return nil
	}
	out := new(CertList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *CertList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CertPolicy) DeepCopyInto(out *CertPolicy) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec
	out.Status = in.Status
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CertPolicy.
func (in *CertPolicy) DeepCopy() *CertPolicy {
	if in == nil {
		return nil
	}
	out := new(CertPolicy)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *CertPolicy) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CertPolicyList) DeepCopyInto(out *CertPolicyList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]CertPolicy, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CertPolicyList.
func (in *CertPolicyList) DeepCopy() *CertPolicyList {
	if in == nil {
		return nil
	}
	out := new(CertPolicyList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *CertPolicyList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CertPolicySpec) DeepCopyInto(out *CertPolicySpec) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CertPolicySpec.
func (in *CertPolicySpec) DeepCopy() *CertPolicySpec {
	if in == nil {
		return nil
	}
	out := new(CertPolicySpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CertPolicyStatus) DeepCopyInto(out *CertPolicyStatus) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CertPolicyStatus.
func (in *CertPolicyStatus) DeepCopy() *CertPolicyStatus {
	if in == nil {
		return nil
	}
	out := new(CertPolicyStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CertReq) DeepCopyInto(out *CertReq) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CertReq.
func (in *CertReq) DeepCopy() *CertReq {
	if in == nil {
		return nil
	}
	out := new(CertReq)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *CertReq) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CertReqList) DeepCopyInto(out *CertReqList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]CertReq, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CertReqList.
func (in *CertReqList) DeepCopy() *CertReqList {
	if in == nil {
		return nil
	}
	out := new(CertReqList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *CertReqList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CertReqSpec) DeepCopyInto(out *CertReqSpec) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	if in.Duration != nil {
		in, out := &in.Duration, &out.Duration
		*out = new(metav1.Duration)
		**out = **in
	}
	out.CASettingRef = in.CASettingRef
	if in.Request != nil {
		in, out := &in.Request, &out.Request
		*out = make([]byte, len(*in))
		copy(*out, *in)
	}
	if in.Usages != nil {
		in, out := &in.Usages, &out.Usages
		*out = make([]KeyUsage, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CertReqSpec.
func (in *CertReqSpec) DeepCopy() *CertReqSpec {
	if in == nil {
		return nil
	}
	out := new(CertReqSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CertReqStatus) DeepCopyInto(out *CertReqStatus) {
	*out = *in
	if in.TLS_CRT != nil {
		in, out := &in.TLS_CRT, &out.TLS_CRT
		*out = make([]byte, len(*in))
		copy(*out, *in)
	}
	if in.CA_CRT != nil {
		in, out := &in.CA_CRT, &out.CA_CRT
		*out = make([]byte, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CertReqStatus.
func (in *CertReqStatus) DeepCopy() *CertReqStatus {
	if in == nil {
		return nil
	}
	out := new(CertReqStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CertSpec) DeepCopyInto(out *CertSpec) {
	*out = *in
	if in.Subject != nil {
		in, out := &in.Subject, &out.Subject
		*out = new(X509Subject)
		(*in).DeepCopyInto(*out)
	}
	if in.Duration != nil {
		in, out := &in.Duration, &out.Duration
		*out = new(metav1.Duration)
		**out = **in
	}
	if in.RenewBefore != nil {
		in, out := &in.RenewBefore, &out.RenewBefore
		*out = new(metav1.Duration)
		**out = **in
	}
	if in.DNSNames != nil {
		in, out := &in.DNSNames, &out.DNSNames
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.IPAddresses != nil {
		in, out := &in.IPAddresses, &out.IPAddresses
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.URIs != nil {
		in, out := &in.URIs, &out.URIs
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.EmailAddresses != nil {
		in, out := &in.EmailAddresses, &out.EmailAddresses
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.SecretTemplate != nil {
		in, out := &in.SecretTemplate, &out.SecretTemplate
		*out = new(CertificateSecretTemplate)
		(*in).DeepCopyInto(*out)
	}
	if in.KeyStores != nil {
		in, out := &in.KeyStores, &out.KeyStores
		*out = new(CertificateKeystores)
		(*in).DeepCopyInto(*out)
	}
	out.CASettingRef = in.CASettingRef
	if in.Usages != nil {
		in, out := &in.Usages, &out.Usages
		*out = make([]KeyUsage, len(*in))
		copy(*out, *in)
	}
	if in.PrivateKey != nil {
		in, out := &in.PrivateKey, &out.PrivateKey
		*out = new(CertificatePrivateKey)
		**out = **in
	}
	if in.EncodeUsagesInRequest != nil {
		in, out := &in.EncodeUsagesInRequest, &out.EncodeUsagesInRequest
		*out = new(bool)
		**out = **in
	}
	if in.RevisionHistoryLimit != nil {
		in, out := &in.RevisionHistoryLimit, &out.RevisionHistoryLimit
		*out = new(int32)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CertSpec.
func (in *CertSpec) DeepCopy() *CertSpec {
	if in == nil {
		return nil
	}
	out := new(CertSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CertStatus) DeepCopyInto(out *CertStatus) {
	*out = *in
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]CertificateCondition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.LastFailureTime != nil {
		in, out := &in.LastFailureTime, &out.LastFailureTime
		*out = (*in).DeepCopy()
	}
	if in.NotBefore != nil {
		in, out := &in.NotBefore, &out.NotBefore
		*out = (*in).DeepCopy()
	}
	if in.NotAfter != nil {
		in, out := &in.NotAfter, &out.NotAfter
		*out = (*in).DeepCopy()
	}
	if in.RenewalTime != nil {
		in, out := &in.RenewalTime, &out.RenewalTime
		*out = (*in).DeepCopy()
	}
	if in.Revision != nil {
		in, out := &in.Revision, &out.Revision
		*out = new(int)
		**out = **in
	}
	if in.NextPrivateKeySecretName != nil {
		in, out := &in.NextPrivateKeySecretName, &out.NextPrivateKeySecretName
		*out = new(string)
		**out = **in
	}
	if in.CertificateRequestName != nil {
		in, out := &in.CertificateRequestName, &out.CertificateRequestName
		*out = new(string)
		**out = **in
	}
	if in.Certificate != nil {
		in, out := &in.Certificate, &out.Certificate
		*out = make([]byte, len(*in))
		copy(*out, *in)
	}
	if in.ReadyTime != nil {
		in, out := &in.ReadyTime, &out.ReadyTime
		*out = (*in).DeepCopy()
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CertStatus.
func (in *CertStatus) DeepCopy() *CertStatus {
	if in == nil {
		return nil
	}
	out := new(CertStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CertificateCondition) DeepCopyInto(out *CertificateCondition) {
	*out = *in
	if in.LastTransitionTime != nil {
		in, out := &in.LastTransitionTime, &out.LastTransitionTime
		*out = (*in).DeepCopy()
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CertificateCondition.
func (in *CertificateCondition) DeepCopy() *CertificateCondition {
	if in == nil {
		return nil
	}
	out := new(CertificateCondition)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CertificateGroup) DeepCopyInto(out *CertificateGroup) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CertificateGroup.
func (in *CertificateGroup) DeepCopy() *CertificateGroup {
	if in == nil {
		return nil
	}
	out := new(CertificateGroup)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CertificateKeystores) DeepCopyInto(out *CertificateKeystores) {
	*out = *in
	if in.JKS != nil {
		in, out := &in.JKS, &out.JKS
		*out = new(JKS)
		**out = **in
	}
	if in.PKCS12 != nil {
		in, out := &in.PKCS12, &out.PKCS12
		*out = new(PKCS12)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CertificateKeystores.
func (in *CertificateKeystores) DeepCopy() *CertificateKeystores {
	if in == nil {
		return nil
	}
	out := new(CertificateKeystores)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CertificatePrivateKey) DeepCopyInto(out *CertificatePrivateKey) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CertificatePrivateKey.
func (in *CertificatePrivateKey) DeepCopy() *CertificatePrivateKey {
	if in == nil {
		return nil
	}
	out := new(CertificatePrivateKey)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CertificateSecretTemplate) DeepCopyInto(out *CertificateSecretTemplate) {
	*out = *in
	if in.Annotations != nil {
		in, out := &in.Annotations, &out.Annotations
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	if in.Labels != nil {
		in, out := &in.Labels, &out.Labels
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CertificateSecretTemplate.
func (in *CertificateSecretTemplate) DeepCopy() *CertificateSecretTemplate {
	if in == nil {
		return nil
	}
	out := new(CertificateSecretTemplate)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Duration) DeepCopyInto(out *Duration) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Duration.
func (in *Duration) DeepCopy() *Duration {
	if in == nil {
		return nil
	}
	out := new(Duration)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ESTSetting) DeepCopyInto(out *ESTSetting) {
	*out = *in
	if in.AuthenticationSecret != nil {
		in, out := &in.AuthenticationSecret, &out.AuthenticationSecret
		*out = new(NamespacedName)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ESTSetting.
func (in *ESTSetting) DeepCopy() *ESTSetting {
	if in == nil {
		return nil
	}
	out := new(ESTSetting)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IssuerCondition) DeepCopyInto(out *IssuerCondition) {
	*out = *in
	if in.LastTransitionTime != nil {
		in, out := &in.LastTransitionTime, &out.LastTransitionTime
		*out = (*in).DeepCopy()
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IssuerCondition.
func (in *IssuerCondition) DeepCopy() *IssuerCondition {
	if in == nil {
		return nil
	}
	out := new(IssuerCondition)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *JKS) DeepCopyInto(out *JKS) {
	*out = *in
	out.Password = in.Password
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new JKS.
func (in *JKS) DeepCopy() *JKS {
	if in == nil {
		return nil
	}
	out := new(JKS)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NamespacedName) DeepCopyInto(out *NamespacedName) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NamespacedName.
func (in *NamespacedName) DeepCopy() *NamespacedName {
	if in == nil {
		return nil
	}
	out := new(NamespacedName)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ObjectReference) DeepCopyInto(out *ObjectReference) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ObjectReference.
func (in *ObjectReference) DeepCopy() *ObjectReference {
	if in == nil {
		return nil
	}
	out := new(ObjectReference)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PKCS12) DeepCopyInto(out *PKCS12) {
	*out = *in
	out.Password = in.Password
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PKCS12.
func (in *PKCS12) DeepCopy() *PKCS12 {
	if in == nil {
		return nil
	}
	out := new(PKCS12)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RenewalJob) DeepCopyInto(out *RenewalJob) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec
	out.Status = in.Status
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RenewalJob.
func (in *RenewalJob) DeepCopy() *RenewalJob {
	if in == nil {
		return nil
	}
	out := new(RenewalJob)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *RenewalJob) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RenewalJobList) DeepCopyInto(out *RenewalJobList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]RenewalJob, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RenewalJobList.
func (in *RenewalJobList) DeepCopy() *RenewalJobList {
	if in == nil {
		return nil
	}
	out := new(RenewalJobList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *RenewalJobList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RenewalJobSpec) DeepCopyInto(out *RenewalJobSpec) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RenewalJobSpec.
func (in *RenewalJobSpec) DeepCopy() *RenewalJobSpec {
	if in == nil {
		return nil
	}
	out := new(RenewalJobSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RenewalJobStatus) DeepCopyInto(out *RenewalJobStatus) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RenewalJobStatus.
func (in *RenewalJobStatus) DeepCopy() *RenewalJobStatus {
	if in == nil {
		return nil
	}
	out := new(RenewalJobStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SelfSignedCASetting) DeepCopyInto(out *SelfSignedCASetting) {
	*out = *in
	if in.CRLDistributionPoints != nil {
		in, out := &in.CRLDistributionPoints, &out.CRLDistributionPoints
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SelfSignedCASetting.
func (in *SelfSignedCASetting) DeepCopy() *SelfSignedCASetting {
	if in == nil {
		return nil
	}
	out := new(SelfSignedCASetting)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *VaultAppRole) DeepCopyInto(out *VaultAppRole) {
	*out = *in
	out.SecretRef = in.SecretRef
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new VaultAppRole.
func (in *VaultAppRole) DeepCopy() *VaultAppRole {
	if in == nil {
		return nil
	}
	out := new(VaultAppRole)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *VaultAuth) DeepCopyInto(out *VaultAuth) {
	*out = *in
	if in.TokenSecretRef != nil {
		in, out := &in.TokenSecretRef, &out.TokenSecretRef
		*out = new(meta.SecretKeySelector)
		**out = **in
	}
	if in.AppRole != nil {
		in, out := &in.AppRole, &out.AppRole
		*out = new(VaultAppRole)
		**out = **in
	}
	if in.Kubernetes != nil {
		in, out := &in.Kubernetes, &out.Kubernetes
		*out = new(VaultKubernetesAuth)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new VaultAuth.
func (in *VaultAuth) DeepCopy() *VaultAuth {
	if in == nil {
		return nil
	}
	out := new(VaultAuth)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *VaultCASetting) DeepCopyInto(out *VaultCASetting) {
	*out = *in
	in.Auth.DeepCopyInto(&out.Auth)
	if in.CABundle != nil {
		in, out := &in.CABundle, &out.CABundle
		*out = make([]byte, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new VaultCASetting.
func (in *VaultCASetting) DeepCopy() *VaultCASetting {
	if in == nil {
		return nil
	}
	out := new(VaultCASetting)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *VaultConfiguration) DeepCopyInto(out *VaultConfiguration) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new VaultConfiguration.
func (in *VaultConfiguration) DeepCopy() *VaultConfiguration {
	if in == nil {
		return nil
	}
	out := new(VaultConfiguration)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *VaultKubernetesAuth) DeepCopyInto(out *VaultKubernetesAuth) {
	*out = *in
	out.SecretRef = in.SecretRef
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new VaultKubernetesAuth.
func (in *VaultKubernetesAuth) DeepCopy() *VaultKubernetesAuth {
	if in == nil {
		return nil
	}
	out := new(VaultKubernetesAuth)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *X509Subject) DeepCopyInto(out *X509Subject) {
	*out = *in
	if in.Organizations != nil {
		in, out := &in.Organizations, &out.Organizations
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.Countries != nil {
		in, out := &in.Countries, &out.Countries
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.OrganizationalUnits != nil {
		in, out := &in.OrganizationalUnits, &out.OrganizationalUnits
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.Localities != nil {
		in, out := &in.Localities, &out.Localities
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.Provinces != nil {
		in, out := &in.Provinces, &out.Provinces
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.StreetAddresses != nil {
		in, out := &in.StreetAddresses, &out.StreetAddresses
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.PostalCodes != nil {
		in, out := &in.PostalCodes, &out.PostalCodes
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new X509Subject.
func (in *X509Subject) DeepCopy() *X509Subject {
	if in == nil {
		return nil
	}
	out := new(X509Subject)
	in.DeepCopyInto(out)
	return out
}