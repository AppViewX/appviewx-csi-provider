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
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	authenticationv1 "k8s.io/api/authentication/v1"
	apicorev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	clientConfig "sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	pb "sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"

	certorchestratorv1 "github.com/AppViewX/appviewx-csi-provider/cert-orchestrator/api/v1"
	v1 "github.com/AppViewX/appviewx-csi-provider/cert-orchestrator/api/v1"
	vaultclient "github.com/AppViewX/appviewx-csi-provider/internal/client"
	"github.com/AppViewX/appviewx-csi-provider/internal/config"
)

var metricsAddr string
var enableLeaderElection bool
var probeAddr string
var mgr manager.Manager
var directClient client.Client

var (
	scheme            = runtime.NewScheme()
	setupLog          = ctrl.Log.WithName("setup")
	waitTimeInSeconds = 5
	maxWaitCount      = 120
	once              = sync.Once{}
)

func setUpClient() {

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8090", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")

	var err error
	mgr, err = ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		MetricsBindAddress:     metricsAddr,
		Port:                   9443,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "394a58ec.certplus.appviewx",
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
		setupLog.V(1).Error(err, "Error in creating Manager")
		return
	}
	setupLog.V(1).Info("Client Created")

	GroupVersion := schema.GroupVersion{Group: "cert-orchestrator.certplus.appviewx", Version: "v1"}
	metav1.AddToGroupVersion(scheme, GroupVersion)
	scheme.AddKnownTypes(GroupVersion, &certorchestratorv1.Cert{}, &certorchestratorv1.CertList{})

	err = apicorev1.AddToScheme(scheme)
	if err != nil {
		setupLog.V(1).Error(err, "Error in AddToScheme")
		return
	}

	directClient, err = client.New(clientConfig.GetConfigOrDie(), client.Options{Scheme: scheme})
	if err != nil {
		setupLog.V(1).Error(err, "Error in waitTillCertificatesAreCreatedAndRetrieveCertificateContents while getting the client : %v")
		return
	}
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

func createCertCRDs(
	ctx context.Context,
	l hclog.Logger,
	certSpecs []v1.CertSpec,
	podName, podNamespace string) ([]v1.Cert, error) {

	l.Info(fmt.Sprintf("Started Creation of Cert for Pod : Name : %s : Namespace : %s",
		podName, podNamespace))
	currentClient := mgr.GetClient()

	certsCreated := []v1.Cert{}

	for _, currentCertSpec := range certSpecs {

		cert := certorchestratorv1.Cert{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:    podNamespace,
				GenerateName: "appviewx-csi-provider" + "-",
			},
			Spec: currentCertSpec,
		}

		err := currentClient.Create(ctx, &cert, &client.CreateOptions{})
		if err != nil {
			l.Info(fmt.Sprintf("Error in create Certificate Pod : Name : %s : Namespace : %s : %v", podName, podNamespace, err))
			return nil, fmt.Errorf("Error in createCertCRDs while create Certificate Pod : Name : %s : Namespace : %s : %w",
				podName, podNamespace, err)
		}
		l.Info(fmt.Sprintf("Created certificate : Name : %s : Namespace : %s", cert.Name, cert.Namespace))
		certsCreated = append(certsCreated, cert)
	}
	l.Info("Cert Creation Success Pod : Name : %s : Namespace : %s", podName, podNamespace)
	return certsCreated, nil
}

func waitTillCertificatesAreCreatedAndRetrieveCertificateContents(
	ctx context.Context,
	l hclog.Logger,
	certs []v1.Cert) error {

	l.Info("Started waitTillCertificatesAreCreatedAndRetrieveCertificateContents")
	currentWaitCount := 0
	var allSecretsReady bool

	certsNameSpacedNames := []types.NamespacedName{}
	for _, currentCert := range certs {
		certsNameSpacedNames = append(certsNameSpacedNames, types.NamespacedName{
			Name:      currentCert.Name,
			Namespace: currentCert.Namespace,
		})
	}

	for currentWaitCount < maxWaitCount && !allSecretsReady {
		time.Sleep(time.Second * time.Duration(waitTimeInSeconds))
		allSecretsReady = true
		for i := 0; i < len(certs); i++ {
			cert := certs[i]

			certificateNamespacedName := types.NamespacedName{
				Name:      cert.Name,
				Namespace: cert.Namespace,
			}
			l.Info(fmt.Sprintf("waitTillCertificatesAreCreatedAndRetrieveCertificateContents - waiting for Certificate : "+
				"currentWaitCount : %d : i : %d certificateNamespacedName:%v", currentWaitCount, i, certificateNamespacedName))

			currentCert := v1.Cert{}
			err := directClient.Get(ctx, certificateNamespacedName, &currentCert)
			if err != nil {
				l.Info(fmt.Sprintf("OK - Error in Getting the Certificate : %v : %v", certificateNamespacedName, err))
				allSecretsReady = false
				break
			}
			if len(currentCert.Status.Certificate) <= 0 {
				allSecretsReady = false
				break
			} else {
				l.Info("Certificate Content available : %v", certificateNamespacedName)
				certs[i] = currentCert
			}
		}
		currentWaitCount++
	}

	if currentWaitCount == maxWaitCount {
		l.Info(fmt.Sprintf("waitTillCertificatesAreCreatedAndRetrieveCertificateContents - Failed : %v", certsNameSpacedNames))
		return fmt.Errorf("Error in waitTillCertificatesAreCreatedAndRetrieveCertificateContents - "+
			"currentWaitCount reached maxWaitCount : %v", certsNameSpacedNames)
	}
	l.Info(fmt.Sprintf("waitTillCertificatesAreCreatedAndRetrieveCertificateContents - Success : %v", certsNameSpacedNames))
	return nil
}

func getSecretContents(
	ctx context.Context,
	l hclog.Logger,
	secretNamespacedNames []types.NamespacedName,
) ([]map[string][]byte, error) {

	l.Info(fmt.Sprintf("Started getSecretContents : %v", secretNamespacedNames))

	output := []map[string][]byte{}

	for _, secretNamespacedName := range secretNamespacedNames {
		secretNamespacedName := types.NamespacedName{
			Name:      secretNamespacedName.Name,
			Namespace: secretNamespacedName.Namespace,
		}
		secret := apicorev1.Secret{}
		err := directClient.Get(ctx, secretNamespacedName, &secret)
		if err != nil {
			l.Error(fmt.Sprintf("Error in getting the Secret : Name : %s : Namespace : %s : %v",
				secretNamespacedName.Name, secretNamespacedName.Namespace, err))
			return nil, fmt.Errorf("Error in getSecretContents : %v : %w", secretNamespacedName, err)
		}
		if len(secret.Data) <= 0 {
			l.Error(fmt.Sprintf("Error in getSecretContents - Length of secret.Data is zero : %v", secretNamespacedName))
			return nil, fmt.Errorf("error in getSecretContents - Length of secret.Data is zero : %v", secretNamespacedName)
		}
		output = append(output, secret.Data)
	}
	l.Info(fmt.Sprintf("Finished getSecretContents : %v", secretNamespacedNames))
	return output, nil
}

// MountSecretsStoreObjectContent mounts content of the vault object to target path
func (p *provider) HandleMountRequest(
	ctx context.Context,
	cfg config.Config,
	flagsConfig config.FlagsConfig,
) (*pb.MountResponse, error) {

	podName := cfg.Parameters.PodInfo.Name
	podNameSpace := cfg.Parameters.PodInfo.Namespace

	p.logger.Info(fmt.Sprintf("Started HandleMountRequest : podName : %s : podNameSpace : %s", podName, podNameSpace))

	once.Do(setUpClient)

	secretNamespacedNames := []types.NamespacedName{}
	for _, certSpec := range cfg.Parameters.CertSpecs {
		secretNamespacedNames = append(secretNamespacedNames, types.NamespacedName{
			Name:      certSpec.SecretName,
			Namespace: podNameSpace,
		})
	}
	p.logger.Info(fmt.Sprintf("Length of secretNamespacedNames : %d : podName : %s : podNameSpace : %s",
		len(secretNamespacedNames), podName, podNameSpace))

	var err error
	var secretContents []map[string][]byte
	if secretContents, err = getSecretContents(ctx, p.logger, secretNamespacedNames); err != nil {
		p.logger.Info(fmt.Sprintf("SecretContents are not available, Creating Certificate CRD : %v", secretNamespacedNames))

		createdCerts, err := createCertCRDs(ctx, p.logger, cfg.Parameters.CertSpecs, podName, podNameSpace)
		if err != nil {
			p.logger.Error(fmt.Sprintf("Error in HandleMountRequest while createCertCRDs : %v", err))
			return nil, fmt.Errorf("Error in HandleMountRequest while createCertCRDs : %w", err)
		}

		err = waitTillCertificatesAreCreatedAndRetrieveCertificateContents(ctx, p.logger, createdCerts)
		if err != nil {
			p.logger.Error(fmt.Sprintf("Error in HandleMountRequest while waitTillCertificatesAreCreatedAndRetrieveCertificateContents : %v", err))
			return nil, fmt.Errorf("Error in HandleMountRequest while waitTillCertificatesAreCreatedAndRetrieveCertificateContent : %w", err)
		}

		//Try to get secrets after a second
		time.Sleep(time.Second)

		secretContents, err = getSecretContents(ctx, p.logger, secretNamespacedNames)
		if err != nil {
			p.logger.Error(fmt.Sprintf("Error in HandleMountRequest while getSecretContents : %v", err))
			return nil, fmt.Errorf("Error in HandleMountRequest while getSecretContents : %w", err)
		}

	} else {
		p.logger.Info(fmt.Sprintf("SecretContents are already available : %v", secretNamespacedNames))
	}

	// Set default k8s auth path if unset.
	if cfg.Parameters.VaultKubernetesMountPath == "" {
		cfg.Parameters.VaultKubernetesMountPath = flagsConfig.VaultMount
	}

	var files []*pb.File
	var objectVersions []*pb.ObjectVersion

	for _, currentSecretContent := range secretContents {

		for k, v := range currentSecretContent {

			files = append(files, &pb.File{Path: k, Mode: int32(cfg.FilePermission), Contents: v})

			objectVersions = append(objectVersions, &pb.ObjectVersion{
				Id: k, Version: "1",
			})
		}
		//TODO: Need to handle for multiple secrets
		break
	}

	p.logger.Info("Finished HandleMountRequest")

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
