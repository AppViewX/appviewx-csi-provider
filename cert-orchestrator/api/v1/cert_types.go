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
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/AppViewX/appviewx-csi-provider/cert-orchestrator/api/v1/meta"
	metaco "github.com/AppViewX/appviewx-csi-provider/cert-orchestrator/api/v1/meta"
)

type Duration struct {
	time.Duration `protobuf:"varint,1,opt,name=duration,casttype=time.Duration"`
}

// +kubebuilder:object:root=true

// Cert is the Schema for the certs API
type Cert struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CertSpec   `json:"spec,omitempty"`
	Status CertStatus `json:"status,omitempty"`
}

//CertSpec expected state of the certificate.
//Any one CommonName or DNSName or URISAN is mandatory
type CertSpec struct {
	//CommonName valid common name for the Certificate
	CommonName            string                     `json:"commonName,omitempty"`
	Subject               *X509Subject               `json:"subject,omitempty"`
	Duration              *metav1.Duration           `json:"duration,omitempty"`
	RenewBefore           *metav1.Duration           `json:"renewBefore,omitempty"`
	DNSNames              []string                   `json:"dnsNames,omitempty"`
	IPAddresses           []string                   `json:"ipAddresses,omitempty"`
	URIs                  []string                   `json:"uris,omitempty"`
	EmailAddresses        []string                   `json:"emailAddresses,omitempty"`
	SecretName            string                     `json:"secretName"`
	SecretTemplate        *CertificateSecretTemplate `json:"secretTemplate,omitempty"`
	KeyStores             *CertificateKeystores      `json:"keystores,omitempty"`
	CASettingRef          ObjectReference            `json:"caSettingRef"`
	IsCA                  bool                       `json:"isCA,omitempty"`
	Usages                []KeyUsage                 `json:"usages,omitempty"`
	PrivateKey            *CertificatePrivateKey     `json:"privateKey,omitempty"`
	EncodeUsagesInRequest *bool                      `json:"encodeUsagesInRequest,omitempty"`
	RevisionHistoryLimit  *int32                     `json:"revisionHistoryLimit,omitempty"`
	CSR                   string                     `json:"csr,omitempty"`
}

// +kubebuilder:object:root=true

// CertList contains a list of Cert
type CertList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Cert `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Cert{}, &CertList{})
}

type X509Subject struct {

	// +optional
	Organizations []string `json:"organizations,omitempty"`

	// +optional
	Countries []string `json:"countries,omitempty"`

	// +optional
	OrganizationalUnits []string `json:"organizationalUnits,omitempty"`

	// +optional
	Localities []string `json:"localities,omitempty"`

	// +optional
	Provinces []string `json:"provinces,omitempty"`

	// +optional
	StreetAddresses []string `json:"streetAddresses,omitempty"`

	// +optional
	PostalCodes []string `json:"postalCodes,omitempty"`

	// +optional
	SerialNumber string `json:"serialNumber,omitempty"`
}

type CertificateSecretTemplate struct {

	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// +optional
	Labels map[string]string `json:"labels,omitempty"`
}

type CertificateKeystores struct {

	// +optional
	JKS *JKS `json:"jks,omitempty"`

	// +optional
	PKCS12 *PKCS12 `json:"pkcs12,omitempty"`
}

type JKS struct {
	Create   bool                   `json:"create"`
	Password meta.SecretKeySelector `json:"password"`
}

type PKCS12 struct {
	Create   bool                   `json:"create"`
	Password meta.SecretKeySelector `json:"password"`
}

//CertificatePrivateKey configuration controls the rotation of PrivateKeys
type CertificatePrivateKey struct {
	//Policy how the Private Keys should be regenerated when a re-issuance is being processed
	//'Never' Generated only iff doesn't exist
	//'Always' will be generated newly
	Policy PrivateKeyRotationPolicy `json:"rotationPolicy,omitempty"`

	//Encoding allowed formats are PKCS1 PKCS8
	//defaults to PKCS1
	Encoding PrivateKeyEncoding `json:"encoding,omitempty"`

	//Algorithm allowed values are RSA, ECDSA
	// for RSA it is 2048, for ECDSA it is 256 are the default key sizes
	Algorithm PrivateKeyAlgorithm `json:"algorithm,omitempty"`

	//Size bit size of the key
	// for RSA  it is 2048, 4096, 8192 , for ECDSA it is 256,384,521 are the supported values
	Size int `json:"size,omitempty"`
}

type PrivateKeyRotationPolicy string

var (
	RotationPolicyNever  PrivateKeyRotationPolicy = "never"
	RotationPolicyAlways PrivateKeyRotationPolicy = "always"
)

type PrivateKeyEncoding string

var (
	PKCS1 PrivateKeyEncoding = "PKCS1"
	PKCS8 PrivateKeyEncoding = "PKCS8"
)

type PrivateKeyAlgorithm string

var (
	RSA   PrivateKeyAlgorithm = "RSA"
	ECDSA PrivateKeyAlgorithm = "ECDSA"
)

//CertStatus observed state of certificate
type CertStatus struct {
	Conditions               []CertificateCondition `json:"conditions,omitempty"`
	LastFailureTime          *metav1.Time           `json:"lastFailureTime,omitempty"`
	NotBefore                *metav1.Time           `json:"notBefore,omitempty"`
	NotAfter                 *metav1.Time           `json:"notAfter,omitempty"`
	RenewalTime              *metav1.Time           `json:"renewalTime,omitempty"`
	Revision                 *int                   `json:"revision,omitempty"`
	NextPrivateKeySecretName *string                `json:"nextPrivateKeySecretName,omitempty"`
	CertificateRequestName   *string                `json:"certificaterequestname,omitempty"`
	Certificate              []byte                 `json:"certificate,omitempty"`
	ReadyTime                *metav1.Time           `json:"readyTime,omitempty"`
}

//CertificateCondition provides the condition information
type CertificateCondition struct {

	//Type allowed values Ready,Issuing
	Type               CertificateConditionType `json:"type"`
	Status             metaco.ConditionStatus   `json:"status"`
	LastTransitionTime *metav1.Time             `json:"lastTransitionTime,omitempty"`
	Reason             string                   `json:"reason,omitempty"`
	Message            string                   `json:"message,omitempty"`
	ObservedGeneration int64                    `json:"observedGeneration,omitempty"`
}

type CertificateConditionType string

const (
	CertificateConditionReady   CertificateConditionType = "Ready"
	CertificateConditionIssuing CertificateConditionType = "Issuing"
	CertificateConditionIssued  string                   = "Issued"
)
