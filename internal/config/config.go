package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/types"

	v1 "github.com/AppViewX/appviewx-csi-provider/cert-orchestrator/api/v1"
	"github.com/AppViewX/appviewx-csi-provider/internal/util"
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
	RoleName       string
	CertSpecs      []v1.CertSpec
	PodInfo        PodInfo
	Audience       string
	ObjectFormat   string
	ObjectEncoding string
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

	parameters.ObjectFormat = params["objectFormat"]
	parameters.ObjectEncoding = params["objectEncoding"]

	secretsYaml := params["objects"]

	//TODO: - Remove yaml to map and back to certSpec conversion
	m1 := make([]map[string]interface{}, 1)
	err = yaml.Unmarshal([]byte(secretsYaml), &m1)
	if err != nil {
		fmt.Println("Error in Unmarshalling Yaml to map : ", err)
		return Parameters{},
			fmt.Errorf("Error in parseParameters : Error in Unmarshalling Yaml to map : %w", err)
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

	if len(c.Parameters.ObjectFormat) == 0 {
		fmt.Printf("ObjectFormat is not given : Setting : %s\n", util.OBJECT_FORMAT_PEM)
		c.Parameters.ObjectFormat = util.OBJECT_FORMAT_PEM
	} else if strings.ToLower(c.Parameters.ObjectFormat) != util.OBJECT_FORMAT_PEM &&
		strings.ToLower(c.Parameters.ObjectFormat) != util.OBJECT_FORMAT_PFX &&
		strings.ToLower(c.Parameters.ObjectFormat) != util.OBJECT_FORMAT_P12 &&
		strings.ToLower(c.Parameters.ObjectFormat) != util.OBJECT_FORMAT_JKS {

		return fmt.Errorf("%s : is not a valid ObjectFormat only %s,%s,%s,%s are supported",
			c.Parameters.ObjectFormat,
			util.OBJECT_FORMAT_PEM, util.OBJECT_FORMAT_PFX,
			util.OBJECT_FORMAT_P12, util.OBJECT_FORMAT_JKS)
	}

	if len(c.Parameters.ObjectEncoding) == 0 {
		fmt.Printf("ObjectEncoding is not given : Setting : %s\n", util.OBJECT_ENCODING_UTF_8)
		c.Parameters.ObjectEncoding = util.OBJECT_ENCODING_UTF_8
	} else if strings.ToLower(c.Parameters.ObjectEncoding) != util.OBJECT_ENCODING_UTF_8 &&
		strings.ToLower(c.Parameters.ObjectEncoding) != util.OBJECT_ENCODING_HEX &&
		strings.ToLower(c.Parameters.ObjectEncoding) != util.OBJECT_ENCODING_BASE_64 {

		return fmt.Errorf("%s : is not a valid ObjectEncoding only %s,%s,%s are supported",
			c.Parameters.ObjectEncoding,
			util.OBJECT_ENCODING_UTF_8, util.OBJECT_ENCODING_HEX, util.OBJECT_ENCODING_BASE_64,
		)
	}

	return nil
}
