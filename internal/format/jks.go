package format

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/rand"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/pavlo-v-chernykh/keystore-go/v4"

	"github.com/AppViewX/appviewx-csi-provider/internal/util"
)

const (
	ALIAS_NAME = "tls1"
)

type Rand struct {
}

type PKCS8Key struct {
	Version             int
	PrivateKeyAlgorithm []asn1.ObjectIdentifier
	PrivateKey          []byte
}

func (r Rand) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = byte(rand.Int31n(9))
	}
	return len(p), nil
}

func marshalPKCS8PrivateKey(key *rsa.PrivateKey, l hclog.Logger) ([]byte, error) {
	l.Debug("Starting marshalPKCS8PrivateKey")
	var pkey PKCS8Key
	pkey.Version = 0
	pkey.PrivateKeyAlgorithm = make([]asn1.ObjectIdentifier, 1)
	pkey.PrivateKeyAlgorithm[0] = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	pkey.PrivateKey = x509.MarshalPKCS1PrivateKey(key)
	output, err := asn1.Marshal(pkey)
	if err != nil {
		l.Error("Error in marshalPKCS8PrivateKey while asn1.Marshal : %v", err)
		return nil, fmt.Errorf("error in marshalPKCS8PrivateKey while asn1.Marshal : %w", err)
	}
	l.Debug("Finished marshalPKCS8PrivateKey")
	return output, nil
}

func getPrivateKey(privateKeyFileContents []byte, l hclog.Logger) ([]byte, error) {
	l.Debug("Starting getPrivateKey")
	block, _ := pem.Decode(privateKeyFileContents)
	if block == nil {
		l.Error("Should have one pem block : error in getPrivateKey ")
		return nil, fmt.Errorf("should have one pem block : error in getPrivateKey")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		l.Error(fmt.Sprintf("Error in getPrivateKey while x509.ParsePKCS1PrivateKey : %v", err))
		return nil, fmt.Errorf("error in getPrivateKey while x509.ParsePKCS1PrivateKey : %w", err)
	}

	output, err := marshalPKCS8PrivateKey(priv, l)
	if err != nil {
		l.Error(fmt.Sprintf("Error in getPrivateKey while marshalPKCS8PrivateKey : %v", err))
		return nil, fmt.Errorf("error in getPrivateKey while marshalPKCS8PrivateKey : %w", err)
	}
	l.Debug("Finished getPrivateKey")
	return output, nil
}

func getKeyStoreCertificate(
	certificateFileContents, caCertificateFileContents []byte,
	l hclog.Logger,
) ([]keystore.Certificate, error) {

	l.Debug("Started getKeyStoreCertificate")

	certificateChain := []keystore.Certificate{}

	l.Debug("Adding Leaf Certificate")
	block, _ := pem.Decode(certificateFileContents)
	if block == nil {
		l.Error("block should not be empty - Error in getKeyStoreCertificate while pem.Decode(certificateFileContents)")
		return nil, fmt.Errorf("block should not be empty - Error in getKeyStoreCertificate while pem.Decode(certificateFileContents)")
	}
	certificateDecodedContents := block.Bytes
	certificateChain = append(certificateChain, keystore.Certificate{
		Type:    "X509",
		Content: certificateDecodedContents})

	l.Debug("Adding Root and Intermediate Certificate")

	for {
		var certDERBlock *pem.Block
		certDERBlock, caCertificateFileContents = pem.Decode(caCertificateFileContents)
		if certDERBlock == nil {
			break
		}
		certificateChain = append(certificateChain, keystore.Certificate{
			Type:    "X509",
			Content: certDERBlock.Bytes})
	}
	l.Debug("Added Root and Intermediate Certificate")

	return certificateChain, nil
}

func GetJKSKeyStoreContents(
	currentSecretContent map[string][]byte,
	l hclog.Logger,
) (
	jksContents []byte,
	jksPassword, aliasName, aliasPassword string,
	err error,
) {

	l.Info("Starting GetJKSKeyStoreContents")

	keyStoreInstance := keystore.New(
		keystore.WithOrderedAliases(),
		keystore.WithCustomRandomNumberGenerator(Rand{}),
	)

	currentTime := time.Now()

	privateKeyFileContents, certificateFileContents, caCertificateFileContents, err :=
		getPrivateKeyCertificateAndCACertificates(currentSecretContent, l)
	if err != nil {
		l.Error(fmt.Sprintf("Error in GetJKSKeyStoreContents while getPrivateKeyCertificateAndCACertificates : %v", err))
		return nil, "", "", "", fmt.Errorf("error in GetJKSKeyStoreContents while getPrivateKeyCertificateAndCACertificates : %w", err)
	}

	certificateChain, err := getKeyStoreCertificate(certificateFileContents, caCertificateFileContents, l)
	if err != nil {
		l.Error(fmt.Sprintf("Error in GetJKSKeyStoreContents while getKeyStoreCertificate : %v", err))
		return nil, "", "", "", fmt.Errorf("error in GetJKSKeyStoreContents while getKeyStoreCertificate : %w", err)
	}

	privateKey, err := getPrivateKey(privateKeyFileContents, l)
	if err != nil {
		l.Error(fmt.Sprintf("Error in GetJKSKeyStoreContents while getPrivateKey : %v", err))
		return nil, "", "", "", fmt.Errorf("error in GetJKSKeyStoreContents while getPrivateKey : %w", err)
	}

	privateKeyEntry := keystore.PrivateKeyEntry{
		CreationTime:     currentTime,
		PrivateKey:       privateKey,
		CertificateChain: certificateChain,
	}

	aliasPassword = util.GetRandomString()

	err = keyStoreInstance.SetPrivateKeyEntry(ALIAS_NAME, privateKeyEntry, []byte(aliasPassword))
	if err != nil {
		l.Error(fmt.Sprintf("error in GetJKSKeyStoreContents while keyStoreInstance.SetPrivateKeyEntry : %v", err))
		return nil, "", "", "", fmt.Errorf("error in GetJKSKeyStoreContents while keyStoreInstance.SetPrivateKeyEntry  : %w", err)
	}

	jksPassword = util.GetRandomString()
	var buffer bytes.Buffer

	err = keyStoreInstance.Store(&buffer, []byte(jksPassword))
	if err != nil {
		l.Error(fmt.Sprintf("error in GetJKSKeyStoreContents while keyStoreInstance.Store : %v", err))
		return nil, "", "", "", fmt.Errorf("error in GetJKSKeyStoreContents while keyStoreInstance.Store : %w", err)
	}

	l.Info("Finished GetJKSKeyStoreContents")

	return buffer.Bytes(), jksPassword, ALIAS_NAME, aliasPassword, nil
}
