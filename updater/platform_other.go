//go:build !windows

package updater

import "fmt"

func platformDirectoryCheck(string) error { return nil }
func NewStage(string) (string, error) {
	return "", fmt.Errorf("обновление доступно только Windows amd64")
}
func LaunchHelper(string, string) error {
	return fmt.Errorf("обновление доступно только Windows amd64")
}
func RunHelper() bool    { return false }
func Acknowledge(string) {}

func installPermissions(string) error { return nil }
