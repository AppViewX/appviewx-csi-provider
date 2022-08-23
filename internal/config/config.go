package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	v1 "github.com/AppViewX/appviewx-csi-provider/cert-orchestrator/api/v1"
	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/types"
)

// Config represents all of the provider's configurable behaviour from the SecretProviderClass,
// transmitted in the MountRequest proto message:
// * Parameters from the `Attributes` field.
// * Plus the rest of the proto fields we consume.
// See sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1/service.pb.go
type Config struct {
	Parameters     Parameters
	TargetPath     string
	FilePermission os.FileMode
}

type FlagsConfig struct {
	Endpoint   string
	Debug      bool
	Version    bool
	HealthAddr string
}

type Parameters struct {
	RoleName  string
	CertSpecs []v1.CertSpec
	PodInfo   PodInfo
	Audience  string
}

type PodInfo struct {
	Name               string
	UID                types.UID
	Namespace          string
	ServiceAccountName string
}

type Secret struct {
	ObjectName     string                 `yaml:"objectName,omitempty"`
	SecretPath     string                 `yaml:"secretPath,omitempty"`
	SecretKey      string                 `yaml:"secretKey,omitempty"`
	Method         string                 `yaml:"method,omitempty"`
	SecretArgs     map[string]interface{} `yaml:"secretArgs,omitempty"`
	FilePermission os.FileMode            `yaml:"filePermission,omitempty"`
}

func Parse(parametersStr, targetPath, permissionStr string) (Config, error) {
	config := Config{
		TargetPath: targetPath,
	}

	var err error
	config.Parameters, err = parseParameters(parametersStr)
	if err != nil {
		return Config{}, err
	}

	if err := json.Unmarshal([]byte(permissionStr), &config.FilePermission); err != nil {
		return Config{}, err
	}

	if err := config.validate(); err != nil {
		return Config{}, err
	}

	return config, nil
}

func parseParameters(parametersStr string) (Parameters, error) {
	var params map[string]string
	err := json.Unmarshal([]byte(parametersStr), &params)
	if err != nil {
		return Parameters{}, err
	}

	var parameters Parameters
	parameters.RoleName = params["roleName"]
	parameters.PodInfo.Name = params["csi.storage.k8s.io/pod.name"]
	parameters.PodInfo.UID = types.UID(params["csi.storage.k8s.io/pod.uid"])
	parameters.PodInfo.Namespace = params["csi.storage.k8s.io/pod.namespace"]
	parameters.PodInfo.ServiceAccountName = params["csi.storage.k8s.io/serviceAccount.name"]
	parameters.Audience = params["audience"]

	secretsYaml := params["objects"]

	//TODO: - Remove yaml to map and back to certSpec conversion
	m1 := make([]map[string]interface{}, 1)
	err = yaml.Unmarshal([]byte(secretsYaml), &m1)
	if err != nil {
		fmt.Println("Error in Unmarshalling Yaml to map : ", err)
		return Parameters{}, fmt.Errorf("Error in parseParameters : Error in Unmarshalling Yaml to map : %w", err)
	}

	c, err := json.Marshal(m1)
	if err != nil {
		fmt.Println("Error in Marshalling map : ", err)
		return Parameters{}, fmt.Errorf("Error in parseParameters : Error in Marshalling map : %w", err)
	}

	err = json.Unmarshal(c, &parameters.CertSpecs)
	if err != nil {
		fmt.Println("Error in json Unmarshalling to parameters.CertSpecs : ", err)
		return Parameters{}, fmt.Errorf("Error in parseParameters : Error in json Unmarshalling to parameters.CertSpecs : %w", err)
	}
	return parameters, nil
}

func (c *Config) validate() error {
	// Some basic validation checks.
	if len(c.Parameters.CertSpecs) == 0 {
		return errors.New("no secrets configured - the provider will not read any secret material")
	}
	return nil
}
