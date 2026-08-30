package core

import (
	"strings"
	"unicode/utf8"

	"golang.org/x/text/encoding/charmap"
)

func decodeCommandOutput(output []byte) string {
	if utf8.Valid(output) {
		return string(output)
	}
	decoded, err := charmap.CodePage866.NewDecoder().Bytes(output)
	if err != nil {
		return strings.ToValidUTF8(string(output), "�")
	}
	return string(decoded)
}

func routeAlreadyExists(output string) bool {
	lower := strings.ToLower(output)
	return strings.Contains(lower, "object already exists") ||
		strings.Contains(lower, "объект уже существует") ||
		strings.Contains(lower, "маршрут уже существует")
}
