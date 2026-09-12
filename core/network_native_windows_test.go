//go:build windows

package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNativeRoutePrefix(t *testing.T) {
	p, err := nativeRoutePrefix("192.0.2.37", "255.255.255.0")
	if err != nil || p.String() != "192.0.2.0/24" {
		t.Fatalf("%v %v", p, err)
	}
	for _, v := range [][2]string{{"::1", "255.255.255.0"}, {"192.0.2.1", "255.0.255.0"}, {"192.0.2.1", "bad"}, {"bad", "255.255.255.0"}} {
		if _, err := nativeRoutePrefix(v[0], v[1]); err == nil {
			t.Fatalf("invalid route accepted: %v", v)
		}
	}
}
func TestNativeCanceledOperationsDoNotTouchNetwork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := physDefault(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if created, err := nativeAddRoute(ctx, "1", netip.MustParsePrefix("192.0.2.0/24"), netip.MustParseAddr("192.0.2.1")); created || !errors.Is(err, context.Canceled) {
		t.Fatalf("%v %v", created, err)
	}

}
func TestNativeLUIDRejectsInvalidIndex(t *testing.T) {
	for _, index := range []string{"0", "-1", "4294967296", "12;exit", ""} {
		if _, err := nativeLUID(index); err == nil {
			t.Fatalf("accepted %q", index)
		}
	}
}

// Явный opt-in: проверка создаёт один временный маршрут TEST-NET-1, не default.
func TestNativeLiveRouteOwnership(t *testing.T) {
	if os.Getenv("CSQTT_NATIVE_LIVE_TEST") != "1" {
		t.Skip("requires explicit native network test")
	}
	ctx := context.Background()
	gateway, index, err := physDefault(ctx)
	if err != nil {
		t.Fatal(err)
	}
	luid, err := nativeLUID(index)
	if err != nil {
		t.Fatal(err)
	}
	prefix := netip.MustParsePrefix("192.0.2.241/32")
	hop := netip.MustParseAddr(gateway)
	if _, err := luid.Route(prefix, hop); err == nil {
		t.Skip("test route already exists; preserve it")
	}
	created, err := nativeAddRoute(ctx, index, prefix, hop)
	if err != nil || !created {
		t.Fatalf("create: %v %v", created, err)
	}
	defer luid.DeleteRoute(prefix, hop)
	if created, err := nativeAddRoute(ctx, index, prefix, hop); err != nil || created {
		t.Fatalf("existing route ownership: %v %v", created, err)
	}
	if err := luid.DeleteRoute(prefix, hop); err != nil {
		t.Fatal(err)
	}
	if _, err := luid.Route(prefix, hop); err == nil {
		t.Fatal("route survived deletion")
	}
}

func TestNativeLiveComparison(t *testing.T) {
	if os.Getenv("CSQTT_NATIVE_LIVE_TEST") != "1" {
		t.Skip("explicit network test only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	gw, index, err := physDefault(ctx)
	if err != nil {
		t.Fatal(err)
	}
	luid, err := nativeLUID(index)
	if err != nil {
		t.Fatal(err)
	}
	prefix := netip.MustParsePrefix("192.0.2.242/32")
	hop := netip.MustParseAddr(gw)
	if _, err := luid.Route(prefix, hop); err == nil {
		t.Skip("test route exists")
	}
	defer luid.DeleteRoute(prefix, hop)
	results := map[string][]float64{}
	measure := func(name string, fn func() error) {
		t.Helper()
		start := time.Now()
		if err := fn(); err != nil {
			t.Fatal(name, err)
		}
		results[name] = append(results[name], time.Since(start).Seconds())
	}
	for i := 0; i < 20; i++ {
		measure("legacy_gateway", func() error {
			out, err := runHiddenContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", `$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object {$_.NextHop -ne '0.0.0.0'} | Sort-Object RouteMetric | Select-Object -First 1; "$($r.NextHop) $($r.InterfaceIndex)"`)
			if err == nil && strings.TrimSpace(out) != gw+" "+index {
				return fmt.Errorf("gateway results differ")
			}
			return err
		})
		measure("native_gateway", func() error {
			g, x, e := physDefault(ctx)
			if e == nil && (g != gw || x != index) {
				return fmt.Errorf("gateway changed during measurement")
			}
			return e
		})
		measure("legacy_dns", func() error {
			out, e := runHiddenContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", fmt.Sprintf(`(Get-DnsClientServerAddress -InterfaceIndex %s -AddressFamily IPv4).ServerAddresses | Select-Object -First 1`, index))
			if e == nil && strings.TrimSpace(out) != physDNS(ctx, index) {
				return fmt.Errorf("DNS results differ")
			}
			return e
		})
		measure("native_dns", func() error {
			if physDNS(ctx, index) == "" {
				return fmt.Errorf("DNS missing")
			}
			return nil
		})
		measure("legacy_route_pair", func() error {
			_, e := runHiddenContext(ctx, "route", "add", "192.0.2.242", "mask", "255.255.255.255", gw, "metric", "1", "IF", index)
			if e != nil {
				return e
			}
			_, e = runHiddenContext(ctx, "route", "delete", "192.0.2.242", "mask", "255.255.255.255", gw, "IF", index)
			return e
		})
		measure("native_route_pair", func() error {
			created, e := nativeAddRoute(ctx, index, prefix, hop)
			if e != nil {
				return e
			}
			if !created {
				return fmt.Errorf("test route remained")
			}
			return luid.DeleteRoute(prefix, hop)
		})
	}
	data, e := json.MarshalIndent(results, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	dest := os.Getenv("CSQTT_NATIVE_REPORT")
	if dest == "" {
		t.Fatal("report path required")
	}
	if e = os.WriteFile(dest, data, 0600); e != nil {
		t.Fatal(e)
	}
	t.Log("20 paired repetitions; gateway and DNS equality verified; temporary route removed")
}
