package constants

const (
	REQUEST_ID_LENGTH = 32
	NAME_LENGTH       = 6
	TLS_CRT           = "tls.crt"
	CA_CRT            = "ca.crt"
	TLS_KEY           = "tls.key"

	NAMESPACE_DEFAULT = "default"

	CONCURRENT_RECONCILES = 5

	//TODO:  - MAKE CONFIGURABLE -
	DEFAULT_RENEWAL_BEFORE_IN_MINUTES = "10m"

	//TODO:  - MAKE CONFIGURABLE -
	DEFAULT_RENEWAL_CRON_IN_MINUTES = 1

	SECRET_NAME_DISCOVERY_APPVIEWX_CREDENTIALS      = "appviewx-credentials-discovery"
	SECRET_NAMESPACE_DISCOVERY_APPVIEWX_CREDENTIALS = "default"

	SECRET_NAME_DISCOVERY_APPVIEWX_ATTRIBUTES      = "appviewx-attributes-discovery"
	SECRET_NAMESPACE_DISCOVERY_APPVIEWX_ATTRIBUTES = "default"
	REQUEST_ID                                     = "request_id"
)
