package util_encode

import (
	"encoding/base64"

	"xops-admin/config"
)

func Encode(s string) string {
	loadConfig, err := config.LoadConfig(".")
	if err != nil {
		return "error load config"
	}
	s = s + loadConfig.API_KEY_BASE64
	data := base64.StdEncoding.EncodeToString([]byte(s))
	return string(data)
}

func Decode(s string) (string, error) {
	loadConfig, err := config.LoadConfig(".")
	if err != nil {
		return "", nil
	}
	s = s + loadConfig.API_KEY_BASE64
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
