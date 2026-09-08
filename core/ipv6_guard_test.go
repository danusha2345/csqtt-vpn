package core

import (
	"errors"
	"testing"
)

func TestIPv6GuardFailsWhenEitherRouteCannotBeInstalled(t *testing.T) {
	denied := errors.New("access denied")
	for _, failed := range []string{"::/1", "8000::/1"} {
		calls := 0
		err := installIPv6Guard(func(prefix string) error {
			calls++
			if prefix == failed {
				return denied
			}
			return nil
		})
		if !errors.Is(err, denied) {
			t.Fatalf("%s failure ignored: %v", failed, err)
		}
		if failed == "::/1" && calls != 1 {
			t.Fatal("continued after guard failure")
		}
	}
}
