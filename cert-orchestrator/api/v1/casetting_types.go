/*


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

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/AppViewX/appviewx-csi-provider/cert-orchestrator/api/v1/meta"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// CASettingSpec defines the desired state of CASetting
type CASettingSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Foo is an example field of CASetting. Edit CASetting_types.go to remove/update
	// Foo string `json:"foo,omitempty"`
	CASettingConfig `json:",inline"`
}

type CASettingConfig struct {

	// +optional
	CA *CACASetting `json:"ca"`

	// +optional
	Vault *VaultCASetting `json:"vault,omitempty"`

	// +optional
	SelfSigned *SelfSignedCASetting `json:"selfSigned,omitempty"`

	// +optional
	AppViewX *AppViewXCASetting `json:"appviewx,omitempty"`

	// +optional
	EST *ESTSetting `json:"est,omitempty"`
}

type ESTSetting struct {
	HostName string `json:"host"`
	Port     int    `json:"port"`

	// +optional
	PathSegment string `json:"pathSegment"`

	AuthenticationSecret *NamespacedName `json:"authenticationSecret"`
}

//TODO:
type AppViewXCASetting struct {
	Host             string           `json:"host"`
	Port             int              `json:"port"`
	IsHttps          bool             `json:"isHttps"`
	CAConnectorInfo  CAConnectorInfo  `json:"caConnectorInfo"`
	Category         string           `json:"category"`
	CertificateGroup CertificateGroup `json:"certificateGroup"`
	// +optional
	Secret *NamespacedName `json:"secret"`
	// +optional
	Vault *VaultConfiguration `json:"vault"`
	// +optional
	IsSync bool `json:"isSync"`
}

type VaultConfiguration struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Name       string `json:"name"`
	EngineType string `json:"engineType"`
}

type CertificateGroup struct {
	Name string `json:"name"`
}

type CAConnectorInfo struct {
	CASettingName        string `json:"caSettingName"`
	CertificateAuthority string `json:"certificateAuthority"`
	// +optional
	CertificateType string `json:"certificateType"`
	// +optional
	ValidityUnit *string `json:"validityUnit"`
	// +optional
	ValidityUnitValue *int `json:"validityUnitValue"`
	//Need to convert to map[string]interface{}
	// +optional
	VendorSpecificDetails *string `json:"vendorSpecificDetails"`

	//+optional
	CertificateProfileName *string `json:"certificateProfileName"`

	//+optional
	IssuerLocation *string `json:"issuerLocation"`

	//+optional
	IssuerName *string `json:"issuerName"`

	//+optional
	Name *string `json:"name"`
}

type NamespacedName struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

type SelfSignedCASetting struct {

	// +optional
	CRLDistributionPoints []string `json:"crlDistributionPoints,omitempty"`
}

type VaultCASetting struct {
	Auth      VaultAuth `json:"auth"`
	Server    string    `json:"server"`
	Path      string    `json:"path"`
	Namespace string    `json:"namespace,omitempty"`
	CABundle  []byte    `json:"caBundle,omitempty"`
}

type VaultAuth struct {

	// +optional
	TokenSecretRef *meta.SecretKeySelector `json:"tokenSecretRef,omitempty"`

	// +optional
	AppRole *VaultAppRole `json:"appRole,omitempty"`

	// +optional
	Kubernetes *VaultKubernetesAuth `json:"kubernetes,omitempty"`
}

type VaultAppRole struct {
	Path string `json:"path"`

	RoleId string `json:"roleId"`

	SecretRef meta.SecretKeySelector `json:"secretRef"`
}

type VaultKubernetesAuth struct {

	// +optional
	Path string `json:"mountPath,omitempty"`

	SecretRef meta.SecretKeySelector `json:"secretRef"`

	Role string `json:"role"`
}

type CACASetting struct {
	SecretName string `json:"secretName"`

	// +optional
	CRLDistributionPoints []string `json:"crlDistributionPoints,omitempty"`

	// +optional
	OCSPServers []string `json:"ocspServers,omitempty"`
}

// CASettingStatus defines the observed state of CASetting
type CASettingStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// +optional
	Conditions []IssuerCondition `json:"conditions,omitempty"`
}

type IssuerCondition struct {
	Type IssuerConditionType `json:"type"`

	Status meta.ConditionStatus `json:"status"`

	// +optional
	LastTransitionTime *metav1.Time `json:"lastTranstionTime,omitempty"`

	// +optional
	Reason string `json:"reason,omitempty"`

	// +optional
	Message string `json:"message,omitempty"`

	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

type IssuerConditionType string

// +kubebuilder:object:root=true

// CASetting is the Schema for the casettings API
type CASetting struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CASettingSpec   `json:"spec,omitempty"`
	Status CASettingStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// CASettingList contains a list of CASetting
type CASettingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CASetting `json:"items"`
}

func init() {
	SchemeBuilder.Register(&CASetting{}, &CASettingList{})
}
