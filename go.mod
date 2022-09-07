module github.com/AppViewX/appviewx-csi-provider

go 1.13

require (
	github.com/go-logr/logr v1.2.0 // indirect
	github.com/hashicorp/go-hclog v1.0.0
	github.com/hashicorp/vault/api v1.2.0
	github.com/hashicorp/yamux v0.0.0-20181012175058-2f1d1f20f75d // indirect
	github.com/stretchr/testify v1.7.2
	google.golang.org/grpc v1.41.0
	gopkg.in/yaml.v3 v3.0.1
	k8s.io/api v0.24.2
	k8s.io/apimachinery v0.24.2
	k8s.io/client-go v0.24.2
	sigs.k8s.io/controller-runtime v0.12.3
	sigs.k8s.io/secrets-store-csi-driver v1.0.0
	software.sslmate.com/src/go-pkcs12 v0.2.0 // indirect
)
