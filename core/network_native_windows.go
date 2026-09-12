//go:build windows

package core

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func nativeLUID(index string) (winipcfg.LUID, error) {
	n, err := strconv.ParseUint(index, 10, 32)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("invalid interface index %q", index)
	}
	return winipcfg.LUIDFromIndex(uint32(n))
}

func physDefault(ctx context.Context) (string, string, error) {
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	routes, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return "", "", err
	}
	var best *winipcfg.MibIPforwardRow2
	var bestMetric uint64
	for i := range routes {
		r := &routes[i]
		if r.DestinationPrefix.Prefix().Bits() != 0 || r.NextHop.Addr().IsUnspecified() {
			continue
		}
		iface, e := r.InterfaceLUID.Interface()
		if e != nil || iface.Alias() == tunName || iface.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}
		ipif, e := r.InterfaceLUID.IPInterface(windows.AF_INET)
		if e != nil {
			continue
		}
		metric := uint64(r.Metric) + uint64(ipif.Metric)
		if best == nil || metric < bestMetric || (metric == bestMetric && r.InterfaceIndex < best.InterfaceIndex) {
			best, bestMetric = r, metric
		}
	}
	if best == nil {
		return "", "", fmt.Errorf("no active IPv4 default route outside %s", tunName)
	}
	return best.NextHop.Addr().String(), strconv.FormatUint(uint64(best.InterfaceIndex), 10), ctx.Err()
}

func physDNS(ctx context.Context, index string) string {
	if ctx.Err() != nil {
		return ""
	}
	luid, err := nativeLUID(index)
	if err != nil {
		return ""
	}
	servers, err := luid.DNS()
	if err != nil {
		return ""
	}
	for _, ip := range servers {
		if ip.Is4() && !ip.IsUnspecified() {
			return ip.String()
		}
	}
	return ""
}

// Возвращает true только для маршрута, созданного этим вызовом. Уже существующий
// маршрут не становится нашей собственностью и не удаляется при отключении.
func nativeAddRoute(ctx context.Context, index string, prefix netip.Prefix, gateway netip.Addr) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	luid, err := nativeLUID(index)
	if err != nil {
		return false, err
	}
	err = luid.AddRoute(prefix.Masked(), gateway, 1)
	created := err == nil
	if err != nil && !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return false, err
	}
	_, check := luid.Route(prefix.Masked(), gateway)
	if check != nil {
		// Даже при сбое readback вызывающий код должен знать о созданном
		// маршруте: он запишет владение и выполнит штатный rollback.
		return created, fmt.Errorf("route readback: %w", check)
	}
	return created, nil
}

func nativeRoutePrefix(network, mask string) (netip.Prefix, error) {
	ip, err := netip.ParseAddr(network)
	if err != nil || !ip.Is4() {
		return netip.Prefix{}, fmt.Errorf("invalid IPv4 route")
	}
	m := net.ParseIP(mask).To4()
	if m == nil {
		return netip.Prefix{}, fmt.Errorf("invalid route mask")
	}
	ones, bits := net.IPMask(m).Size()
	if bits != 32 {
		return netip.Prefix{}, fmt.Errorf("non-contiguous route mask")
	}
	return netip.PrefixFrom(ip, ones).Masked(), nil
}
