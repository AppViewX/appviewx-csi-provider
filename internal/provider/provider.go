package provider

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	authenticationv1 "k8s.io/api/authentication/v1"
	apicorev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	pb "sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"

	certorchestratorv1 "github.com/AppViewX/appviewx-csi-provider/cert-orchestrator/api/v1"
	v1 "github.com/AppViewX/appviewx-csi-provider/cert-orchestrator/api/v1"
	vaultclient "github.com/AppViewX/appviewx-csi-provider/internal/client"
	"github.com/AppViewX/appviewx-csi-provider/internal/config"
)

var metricsAddr string
var enableLeaderElection bool
var probeAddr string

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8090", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
}

// provider implements the secrets-store-csi-driver provider interface
// and communicates with the Vault API.
type provider struct {
	logger hclog.Logger
	cache  map[cacheKey]*api.Secret

	// Allows mocking Kubernetes API for tests.
	k8sClient kubernetes.Interface
}

func NewProvider(logger hclog.Logger, k8sClient kubernetes.Interface) *provider {
	p := &provider{
		logger:    logger,
		cache:     make(map[cacheKey]*api.Secret),
		k8sClient: k8sClient,
	}

	return p
}

type cacheKey struct {
	secretPath string
	method     string
}

func (p *provider) createJWTToken(ctx context.Context, podInfo config.PodInfo, audience string) (string, error) {
	p.logger.Debug("creating service account token bound to pod",
		"namespace", podInfo.Namespace,
		"serviceAccountName", podInfo.ServiceAccountName,
		"podName", podInfo.Name,
		"podUID", podInfo.UID)

	ttl := int64((15 * time.Minute).Seconds())
	audiences := []string{}
	if audience != "" {
		audiences = []string{audience}
	}
	resp, err := p.k8sClient.CoreV1().ServiceAccounts(podInfo.Namespace).CreateToken(ctx, podInfo.ServiceAccountName, &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			ExpirationSeconds: &ttl,
			Audiences:         audiences,
			BoundObjectRef: &authenticationv1.BoundObjectReference{
				Kind:       "Pod",
				APIVersion: "v1",
				Name:       podInfo.Name,
				UID:        podInfo.UID,
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to create a service account token for requesting pod %v: %w", podInfo, err)
	}

	p.logger.Debug("service account token creation successful")
	return resp.Status.Token, nil
}

func (p *provider) login(ctx context.Context, client *api.Client, params config.Parameters) error {
	p.logger.Debug("performing vault login")

	jwt, err := p.createJWTToken(ctx, params.PodInfo, params.Audience)
	if err != nil {
		return err
	}

	req := client.NewRequest(http.MethodPost, "/v1/auth/"+params.VaultKubernetesMountPath+"/login")
	err = req.SetJSONBody(map[string]string{
		"role": params.VaultRoleName,
		"jwt":  jwt,
	})
	if err != nil {
		return err
	}
	secret, err := vaultclient.Do(ctx, client, req)
	if err != nil {
		return fmt.Errorf("failed to login: %w", err)
	}

	client.SetToken(secret.Auth.ClientToken)

	p.logger.Debug("vault login successful")
	return nil
}

func ensureV1Prefix(s string) string {
	switch {
	case strings.HasPrefix(s, "/v1/"):
		return s
	case strings.HasPrefix(s, "v1/"):
		return "/" + s
	case strings.HasPrefix(s, "/"):
		return "/v1" + s
	default:
		return "/v1/" + s
	}
}

func generateRequest(client *api.Client, secret config.Secret) (*api.Request, error) {
	secretPath := ensureV1Prefix(secret.SecretPath)
	queryIndex := strings.Index(secretPath, "?")
	var queryParams map[string][]string
	if queryIndex != -1 {
		var err error
		queryParams, err = url.ParseQuery(secretPath[queryIndex+1:])
		if err != nil {
			return nil, fmt.Errorf("failed to parse query parameters from secretPath %q for objectName %q: %w", secretPath, secret.ObjectName, err)
		}
		secretPath = secretPath[:queryIndex]
	}
	method := http.MethodGet
	if secret.Method != "" {
		method = secret.Method
	}

	req := client.NewRequest(method, secretPath)
	if queryParams != nil {
		req.Params = queryParams
	}
	if secret.SecretArgs != nil {
		err := req.SetJSONBody(secret.SecretArgs)
		if err != nil {
			return nil, err
		}
	}

	return req, nil
}

func keyFromData(rootData map[string]interface{}, secretKey string) ([]byte, error) {
	// Automatically parse through to embedded .data.data map if it's present
	// and the correct type (e.g. for kv v2).
	var data map[string]interface{}
	d, ok := rootData["data"]
	if ok {
		data, ok = d.(map[string]interface{})
	}
	if !ok {
		data = rootData
	}

	// Fail early if a the key does not exist in the secret
	if _, ok := data[secretKey]; !ok {
		return nil, fmt.Errorf("key %q does not exist at the secret path", secretKey)
	}

	// Special-case the most common format of strings so the contents are
	// returned plainly without quotes that json.Marshal would add.
	if content, ok := data[secretKey].(string); ok {
		return []byte(content), nil
	}

	// Arbitrary data can be returned in the data field of an API secret struct.
	// It's already been Unmarshalled from the response, so in theory,
	// marshalling should never realistically fail, but don't log the error just
	// in case, as it could contain secret contents if it does somehow fail.
	if content, err := json.Marshal(data[secretKey]); err == nil {
		return content, nil
	}

	return nil, fmt.Errorf("failed to extract secret content as string or JSON from key %q", secretKey)
}

func (p *provider) getSecret(ctx context.Context, client *api.Client, secretConfig config.Secret) ([]byte, error) {
	var secret *api.Secret
	var cached bool
	key := cacheKey{secretPath: secretConfig.SecretPath, method: secretConfig.Method}
	if secret, cached = p.cache[key]; !cached {
		req, err := generateRequest(client, secretConfig)
		if err != nil {
			return nil, err
		}
		p.logger.Debug("Requesting secret", "secretConfig", secretConfig, "method", req.Method, "path", req.URL.Path, "params", req.Params)

		if err != nil {
			return nil, fmt.Errorf("could not generate request: %v", err)
		}

		secret, err = vaultclient.Do(ctx, client, req)
		if err != nil {
			return nil, fmt.Errorf("couldn't read secret %q: %w", secretConfig.ObjectName, err)
		}
		if secret == nil || secret.Data == nil {
			return nil, fmt.Errorf("empty response from %q, warnings: %v", req.URL.Path, secret.Warnings)
		}

		for _, w := range secret.Warnings {
			p.logger.Warn("warning in response from Vault API", "warning", w)
		}

		p.cache[key] = secret
	} else {
		p.logger.Debug("Secret fetched from cache", "secretConfig", secretConfig)
	}

	// If no secretKey specified, we return the whole response as a JSON object.
	if secretConfig.SecretKey == "" {
		content, err := json.Marshal(secret)
		if err != nil {
			return nil, err
		}

		return content, nil
	}

	value, err := keyFromData(secret.Data, secretConfig.SecretKey)
	if err != nil {
		return nil, fmt.Errorf("{%s}: {%w}", secretConfig.SecretPath, err)
	}

	return value, nil
}

func createCert(l hclog.Logger) {

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		MetricsBindAddress:     metricsAddr,
		Port:                   9443,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "394a2dc7.certplus.appviewx",
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		// LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		l.Info("Error in create Cert ", err)
		return
	}
	currentClient := mgr.GetClient()
	l.Info("Client Created")

	GroupVersion := schema.GroupVersion{Group: "cert-orchestrator.certplus.appviewx", Version: "v1"}

	// // SchemeBuilder is used to add go types to the GroupVersionKind scheme
	// SchemeBuilder := &controllerRuntimeScheme.Builder{GroupVersion: GroupVersion}

	// SchemeBuilder = SchemeBuilder.Register(&certorchestratorv1.Cert{}, &certorchestratorv1.CertList{})
	// // AddToScheme adds the types in this group-version to the given scheme.
	// // AddToScheme = SchemeBuilder.AddToScheme

	// _, err3 := SchemeBuilder.Build()
	// if err3 != nil {
	// 	l.Info("Error in SchemeBuilder ", err3)
	// 	return
	// }

	metav1.AddToGroupVersion(scheme, GroupVersion)
	scheme.AddKnownTypes(GroupVersion, &certorchestratorv1.Cert{}, &certorchestratorv1.CertList{})

	err = apicorev1.AddToScheme(scheme)
	if err != nil {
		l.Info("Error in AddToScheme", err)
		return
	}

	ctx := context.Background()
	createCertCRD(ctx, l, currentClient)
	createSecret(ctx, l, currentClient)
}

func createSecret(ctx context.Context, l hclog.Logger, currentClient client.Client) {
	l.Info("Started Creation of Secret")
	secret := apicorev1.Secret{}
	secret.Name = "testsecretappviewxprovider"
	secret.Namespace = "test"

	secret.Data = map[string][]byte{}

	secret.Data["tls.crt"] = []byte("AppViewX-Provider-tls.crt")
	secret.Data["ca.crt"] = []byte("AppViewX-Provider-ca.crt")
	l.Info("Secret Ready")

	err1 := currentClient.Create(ctx, &secret, &client.CreateOptions{})
	if err1 != nil {
		l.Info("Error in create Secret", err1)
		// return
	}

	l.Info("Secret Creation Success")
}

func createCertCRD(ctx context.Context, l hclog.Logger, currentClient client.Client) {
	l.Info("Started Creation of Cert")

	cert := certorchestratorv1.Cert{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:    "test",
			GenerateName: "myname" + "-",
		},

		Spec: v1.CertSpec{
			CommonName: "test.com",
		},
	}

	err2 := currentClient.Create(ctx, &cert, &client.CreateOptions{})
	if err2 != nil {
		l.Info("Error in create Certificate : %v", err2)
		return
	}

	l.Info("Cert Creation Success")

}

// MountSecretsStoreObjectContent mounts content of the vault object to target path
func (p *provider) HandleMountRequest(ctx context.Context, cfg config.Config, flagsConfig config.FlagsConfig) (*pb.MountResponse, error) {

	p.logger.Info(fmt.Sprintf("*** cfg.Parameters.VaultAddress : %s", cfg.Parameters.VaultAddress))
	p.logger.Info(fmt.Sprintf("*** cfg.Parameters.VaultRoleName : %s", cfg.Parameters.VaultRoleName))
	p.logger.Info(fmt.Sprintf("*** cfg.Parameters.VaultKubernetesMountPath : %s", cfg.Parameters.VaultKubernetesMountPath))
	p.logger.Info(fmt.Sprintf("*** cfg.Parameters.VaultNamespace : %s", cfg.Parameters.VaultNamespace))
	p.logger.Info(fmt.Sprintf("*** cfg.Parameters.Secrets : %s", cfg.Parameters.CertSpecs))
	for _, certSpec := range cfg.Parameters.CertSpecs {
		p.logger.Info(fmt.Sprintf("***** certSpec.CommonName : %s", certSpec.CommonName))
		p.logger.Info(fmt.Sprintf("***** certSpec.Duration : %v", certSpec.Duration))
	}
	p.logger.Info(fmt.Sprintf("*** cfg.Parameters.PodInfo.Name : %s", cfg.Parameters.PodInfo.Name))
	p.logger.Info(fmt.Sprintf("*** cfg.Parameters.PodInfo.Namespace : %s", cfg.Parameters.PodInfo.Namespace))
	p.logger.Info(fmt.Sprintf("*** cfg.Parameters.PodInfo.ServiceAccountName : %s", cfg.Parameters.PodInfo.ServiceAccountName))
	p.logger.Info(fmt.Sprintf("*** cfg.Parameters.PodInfo.UID : %s", cfg.Parameters.PodInfo.UID))
	p.logger.Info(fmt.Sprintf("*** cfg.Parameters.Audience : %s", cfg.Parameters.Audience))
	p.logger.Info(fmt.Sprintf("*** cfg.TargetPath : %s", cfg.TargetPath))
	p.logger.Info(fmt.Sprintf("*** cfg.FilePermission : %s", cfg.FilePermission))

	p.logger.Info("************* Started HandleMountRequest ********************")

	// client, err := vaultclient.New(cfg.Parameters, flagsConfig)
	// if err != nil {
	// 	return nil, err
	// }

	createCert(p.logger)

	// Set default k8s auth path if unset.
	if cfg.Parameters.VaultKubernetesMountPath == "" {
		cfg.Parameters.VaultKubernetesMountPath = flagsConfig.VaultMount
	}

	// Authenticate to vault using the jwt token
	// err = p.login(ctx, client, cfg.Parameters)
	// if err != nil {
	// 	return nil, err
	// }

	var files []*pb.File
	var objectVersions []*pb.ObjectVersion
	// for _, secret := range cfg.Parameters.Secrets {
	// 	content, err := p.getSecret(ctx, client, secret)
	// 	if err != nil {
	// 		return nil, err
	// 	}

	// 	version, err := generateObjectVersion(secret, content)
	// 	if err != nil {
	// 		return nil, fmt.Errorf("failed to generate version for object name %q: %w", secret.ObjectName, err)
	// 	}

	// 	filePermission := int32(cfg.FilePermission)
	// 	if secret.FilePermission != 0 {
	// 		filePermission = int32(secret.FilePermission)
	// 	}
	// 	p.logger.Info(fmt.Sprintf("***** secret.ObjectName : %s", secret.ObjectName))
	// 	p.logger.Info(fmt.Sprintf("***** filePermission : %d", filePermission))
	// 	p.logger.Info(fmt.Sprintf("***** content : %s", string(content)))

	// 	files = append(files, &pb.File{Path: secret.ObjectName + "_1", Mode: filePermission, Contents: content})
	// 	files = append(files, &pb.File{Path: secret.ObjectName + "_2", Mode: filePermission, Contents: content})
	// 	objectVersions = append(objectVersions, version)
	// 	p.logger.Info("secret added to mount response", "directory", cfg.TargetPath, "file", secret.ObjectName)
	// }

	files = append(files, &pb.File{Path: "tls.crt", Mode: int32(cfg.FilePermission), Contents: []byte("*** AppViewX tls.crt***")})
	files = append(files, &pb.File{Path: "tls.key", Mode: int32(cfg.FilePermission), Contents: []byte("*** AppViewX tls.key***")})
	files = append(files, &pb.File{Path: "ca.crt", Mode: int32(cfg.FilePermission), Contents: []byte("*** AppViewX ca.crt***")})

	objectVersions = append(objectVersions, &pb.ObjectVersion{
		Id:      "tls.crt",
		Version: "1",
	})
	objectVersions = append(objectVersions, &pb.ObjectVersion{
		Id:      "tls.key",
		Version: "1",
	})
	objectVersions = append(objectVersions, &pb.ObjectVersion{
		Id:      "ca.crt",
		Version: "1",
	})

	return &pb.MountResponse{
		Files:         files,
		ObjectVersion: objectVersions,
	}, nil
}

func generateObjectVersion(secret config.Secret, content []byte) (*pb.ObjectVersion, error) {
	hash := sha256.New()
	// We include the secret config in the hash input to avoid leaking information
	// about different secrets that could have the same content.
	_, err := hash.Write([]byte(fmt.Sprintf("%v:%s", secret, content)))
	if err != nil {
		return nil, err
	}

	return &pb.ObjectVersion{
		Id:      secret.ObjectName,
		Version: base64.URLEncoding.EncodeToString(hash.Sum(nil)),
	}, nil
}
