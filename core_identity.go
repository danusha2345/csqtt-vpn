package main

import (
	"csqtt-vpn/updater"
	_ "embed"
	"encoding/json"
	"os"
	"path/filepath"
)

//go:embed core_identity.json
var coreIdentityJSON []byte

func bundledCoreIdentity(path string) string {
	var identity struct {
		Version string            `json:"version"`
		SHA256  map[string]string `json:"sha256"`
	}
	if json.Unmarshal(coreIdentityJSON, &identity) != nil {
		return "неизвестная версия core"
	}
	expected := identity.SHA256[filepath.Base(path)]
	stat, err := os.Stat(path)
	if err != nil || !stat.Mode().IsRegular() || stat.Size() > 32<<20 || expected == "" {
		return "core отсутствует или не соответствует bundle"
	}
	actual, err := updater.HashFile(path)
	if err != nil || actual != expected {
		return "SHA-256 core не соответствует bundle"
	}
	return identity.Version + " (SHA-256 проверен)"
}
