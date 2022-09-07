package util

import (
	"crypto/md5"
	"encoding/hex"
	"math/rand"
	"time"
)

const (
	OBJECT_FORMAT_PEM = "pem"
	OBJECT_FORMAT_PFX = "pfx"

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
