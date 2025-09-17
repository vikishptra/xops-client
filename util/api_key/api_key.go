package util_apikey

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

func GenerateSecureAPIKey() string {
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return ""
	}

	randomString := base64.URLEncoding.EncodeToString(randomBytes)

	timestamp := time.Now().Unix()

	apiKey := fmt.Sprintf("%s_%d_%s",
		"sk",
		timestamp,
		strings.TrimRight(randomString, "="),
	)

	return apiKey
}
