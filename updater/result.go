package updater

import (
	"os"
	"path/filepath"
	"strings"
)

// LastResult читает только bounded локальный журнал; не исполняет его содержимое.
func LastResult(install string) string {
	entries, e := os.ReadDir(install)
	if e != nil {
		return ""
	}
	var message string
	var newest int64
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), ".csqtt-update-") {
			continue
		}
		stage := filepath.Join(install, entry.Name())
		if CheckDirectory(stage) != nil {
			continue
		}
		p := filepath.Join(stage, "error.txt")
		i, e := os.Lstat(p)
		if e != nil || !i.Mode().IsRegular() || i.Size() > 16384 {
			continue
		}
		if i.ModTime().UnixNano() < newest {
			continue
		}
		b, e := os.ReadFile(p)
		if e != nil {
			continue
		}
		newest = i.ModTime().UnixNano()
		message = "Предыдущая попытка обновления: " + string(b) + "\nЖурнал/backup: " + stage
	}
	return message
}
