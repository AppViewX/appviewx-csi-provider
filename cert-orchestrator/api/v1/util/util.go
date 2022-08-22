package util

import (
	"fmt"
	"math/rand"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/types"

	v1 "github.com/AppViewX/appviewx-csi-provider/cert-orchestrator/api/v1"
	"github.com/AppViewX/appviewx-csi-provider/cert-orchestrator/api/v1/util/constants"
)

// CertificateHasGivenCondition will return true if the given certificate's status conditions
// has one of the CertificateCondition matching
func CertificateHasGivenCondition(
	cert *v1.Cert,
	c v1.CertificateCondition,
) bool {

	if cert == nil {
		return false
	}

	for _, currentCondition := range cert.Status.Conditions {

		if c.Type == currentCondition.Type &&
			c.Status == currentCondition.Status &&
			c.Reason == currentCondition.Reason {

			return true
		}
	}

	return false

}

// RandSeq will generate a random string with 'n' number of characters in it
func RandSeq(
	n int,
) string {

	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	b := make([]rune, n)

	for i := range b {

		b[i] = letters[rand.Intn(len(letters))]
	}

	return string(b)

}

// GetLogObject will add the requestId ( Random string ) along with the controller name
// and the current object in process in the controller
func GetLogObject(
	inputLog logr.Logger,
	controllerName string,
	namespacedName types.NamespacedName,
) (logr.Logger, string) {

	randString := RandSeq(constants.REQUEST_ID_LENGTH)
	return inputLog.WithValues(controllerName, namespacedName,
		constants.REQUEST_ID, randString), randString
}

// GetRecoveryHandlerFunc returns the recovery handler function
func GetRecoveryHandlerFunc(
	l logr.Logger,
	randString string,
	namespacedName types.NamespacedName,
	controllerName string,
	objectName string,
) func() {

	return func() {
		r := recover()
		if r != nil {

			err := fmt.Errorf("recovery error at %s : %s : %s request_id : %s",
				objectName, controllerName, namespacedName, randString)
			l.V(1).Error(err, fmt.Sprintf("Error - recovered from a panic : %+v", r))

		}
	}
}

func GetFullName(namespace, name string) string {
	return fmt.Sprintf("%s/%s", namespace, name)
}
