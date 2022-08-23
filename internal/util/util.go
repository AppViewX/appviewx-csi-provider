package util

import (
	"crypto/md5"
	"encoding/hex"
)

func GetMD5Hash(input []byte) string {
	hash := md5.Sum(input)
	return hex.EncodeToString(hash[:])
}
