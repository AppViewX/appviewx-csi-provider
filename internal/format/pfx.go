package format

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"

	"github.com/hashicorp/go-hclog"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/AppViewX/appviewx-csi-provider/internal/util"
)

func getPrivateKeyCertificateAndCACertificates(
	currentSecretContent map[string][]byte,
	l hclog.Logger,
) (
	privateKeyFileContents, certificateFileContents, caCertificateFileContents []byte,
	err error,
) {
	var ok bool
	privateKeyFileContents, ok = currentSecretContent["tls.key"]
	if !ok || len(privateKeyFileContents) <= 0 {
		l.Error("error in getPrivateKeyCertificateAndCACertificates tls.key is not available")
		return nil, nil, nil, fmt.Errorf("error in getPrivateKeyCertificateAndCACertificates : tls.key is not available ")
	}

	certificateFileContents, ok = currentSecretContent["tls.crt"]
	if !ok || len(certificateFileContents) <= 0 {
		l.Error("error in getPrivateKeyCertificateAndCACertificates tls.crt is not available")
		return nil, nil, nil, fmt.Errorf("error in getPrivateKeyCertificateAndCACertificates : tls.crt is not available")
	}

	caCertificateFileContents, ok = currentSecretContent["ca.crt"]
	if !ok || len(caCertificateFileContents) <= 0 {
		l.Error("error in getPrivateKeyCertificateAndCACertificates ca.crt is not available")
		return nil, nil, nil, fmt.Errorf("error in getPrivateKeyCertificateAndCACertificates ca.crt is not available")
	}
	return
}

func GetPfxContentForSecret(currentSecretContent map[string][]byte, l hclog.Logger) ([]byte, string, error) {

	l.Debug("Starting getPfxContentForSecret")

	privateKeyFileContents, certificateFileContents, caCertificateFileContents, err :=
		getPrivateKeyCertificateAndCACertificates(currentSecretContent, l)
	if err != nil {
		l.Error(fmt.Sprintf("Error in GetPfxContentForSecret while getPrivateKeyCertificateAndCACertificates : %v", err))
		return nil, "", fmt.Errorf("error in GetPfxContentForSecret while getPrivateKeyCertificateAndCACertificates : %w", err)
	}

	block, _ := pem.Decode(privateKeyFileContents)
	if block == nil {
		l.Error("error in GetPfxContentForSecret while Decoding PrivateKey")
		return nil, "", fmt.Errorf("error in GetPfxContentForSecret while Decoding PrivateKey")
	}

	var keyBytes *rsa.PrivateKey
	if block != nil {
		keyBytes, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			l.Debug("Error in GetPfxContentForSecret while ParsePKCS1PrivateKey: %v", err)
			return nil, "", fmt.Errorf("error in GetPfxContentForSecret while ParsePKCS1PrivateKey : %w", err)
		}
	}

	signedCert, err := getCertificateFromContents(certificateFileContents, l)
	if err != nil {
		log.Println("Error in GetPfxContentForSecret while  getCertificateFromContents", err)
		return nil, "", fmt.Errorf("error in GetPfxContentForSecret while getCertificateFromContents : %w", err)
	}

	caCerts, err := getCACerts(caCertificateFileContents, l)
	if err != nil {
		log.Println("Error in GetPfxContentForSecret while getCACerts", err)
		return nil, "", fmt.Errorf("error in GetPfxContentForSecret while getCACerts : %w", err)
	}

	password := util.GetRandomString()

	l.Info("Generating the pfx file")
	pfxData, err := pkcs12.Encode(rand.Reader, keyBytes, signedCert, caCerts, password)
	if err != nil {
		log.Println("Error in GetPfxContentForSecret while pkcs12.Encode", err)
		return nil, "", fmt.Errorf("error in GetPfxContentForSecret while pkcs12.Encode : %w", err)
	}

	l.Debug("Finished GetPfxContentForSecret")
	return pfxData, password, nil
}

func getCertificateFromContents(certificateContents []byte, l hclog.Logger) (cert *x509.Certificate, err error) {
	l.Debug("Starting getCertificateFromContents")
	block, _ := pem.Decode(certificateContents)
	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		l.Error(fmt.Sprintf("error in getCertificateFromContents while ParseCertificate : %v", err))
		return nil, fmt.Errorf("error in getCertificateFromContents while ParseCertificate : %w", err)
	}
	l.Debug("Finished getCertificateFromContents")
	return
}

func getCACerts(caCertificateFileContents []byte, l hclog.Logger) (output []*x509.Certificate, err error) {
	l.Debug("Starting getCACerts")
	var blocks [][]byte

	for {
		var certDERBlock *pem.Block
		certDERBlock, caCertificateFileContents = pem.Decode(caCertificateFileContents)
		if certDERBlock == nil {
			break
		}
		blocks = append(blocks, certDERBlock.Bytes)
	}

	for _, block := range blocks {
		cert, err := x509.ParseCertificate(block)
		if err != nil {
			l.Error("Error in getCACerts while ParseCertificate : %v", err)
			return nil, fmt.Errorf("error in getCACerts while parseCertificate : %w", err)
		}
		output = append(output, cert)
	}
	l.Debug("Finished getCACerts")
	return
}
