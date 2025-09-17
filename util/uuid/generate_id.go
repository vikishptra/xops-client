package util_uuid

import (
	"strings"

	"github.com/google/uuid"
)

func GenerateID() string {
	ID := uuid.New().String()
	return ID
}
func Capitalize(s string) string {
	if len(s) == 0 {
		return s
	}
	return strings.ToUpper(s[:1]) + strings.ToLower(s[1:])
}
