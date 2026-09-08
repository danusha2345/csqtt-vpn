package updater

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type Ticket struct {
	Version string
	Hash    string
}

func WriteTicket(stage, version, hash string) error {
	b, e := json.Marshal(Ticket{version, hash})
	if e != nil {
		return e
	}
	return os.WriteFile(filepath.Join(stage, "ticket.json"), b, 0600)
}
