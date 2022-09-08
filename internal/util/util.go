package util

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"time"

	"github.com/hashicorp/go-hclog"
)

const (
	OBJECT_FORMAT_PEM = "pem"
	OBJECT_FORMAT_PFX = "pfx"
	OBJECT_FORMAT_JKS = "jks"

	OBJECT_ENCODING_UTF_8   = "utf-8"
	OBJECT_ENCODING_HEX     = "hex"
	OBJECT_ENCODING_BASE_64 = "base64"
)

func GetMD5Hash(input []byte) string {
	hash := md5.Sum(input)
	return hex.EncodeToString(hash[:])
}

//GetRandomString - provides a random string
func GetRandomString() string {
	s1 := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(s1)
	// return strconv.Itoa(r1.Intn(10000))
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	contents := make([]rune, 16)
	for i := range contents {
		contents[i] = letters[r1.Intn(len(letters))]
	}
	return string(contents)
}

func Encode(input []byte, objectEncodingFormat string, l hclog.Logger) (output []byte, err error) {
	l.Debug("Starting encode")

	switch objectEncodingFormat {

	case OBJECT_ENCODING_BASE_64:
		l.Info(fmt.Sprintf("Doing : %s", OBJECT_ENCODING_BASE_64))
		output = make([]byte, base64.StdEncoding.EncodedLen(len(input)))
		base64.StdEncoding.Encode(output, input)
		return

	case OBJECT_ENCODING_HEX:
		l.Info(fmt.Sprintf("Doing : %s", OBJECT_ENCODING_HEX))
		output = make([]byte, hex.EncodedLen(len(input)))
		hex.Encode(output, input)
		return

	case OBJECT_ENCODING_UTF_8:
		l.Info(fmt.Sprintf("Doing : %s", OBJECT_ENCODING_UTF_8))
		output = input
		return

	default:
		return nil, fmt.Errorf("error in encode : %s is not supported", objectEncodingFormat)
	}
}
