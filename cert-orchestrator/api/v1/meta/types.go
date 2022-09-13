package meta

type ObjectReference struct {
	Name string `json:"name"`

	// +optional
	Kind string `json:"kind,omitempty"`

	//+ optional
	Group string `json:"group,omitempty"`
}

type LocalObjectReference struct {
	Name string `json:"name"`
}

type SecretKeySelector struct {
	LocalObjectReference `json:",inline"`
	Key                  string `json:"key,omitempty"`
}

// +kubebuilder:validation:Enum=True;False;Unknown
type ConditionStatus string

const (
	ConditionTrue    ConditionStatus = "True"
	ConditionFalse   ConditionStatus = "False"
	ConditionUnknown ConditionStatus = "Unknown"
)
