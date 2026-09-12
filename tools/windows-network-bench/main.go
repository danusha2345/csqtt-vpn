package main

import (
	"context"
	"csqtt-vpn/core"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/miekg/dns"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

func main() {
	if runtime.GOOS != "windows" {
		panic("Windows-only benchmark")
	}
	n := flag.Int("n", 20, "cycles")
	cancelMS := flag.Int("cancel-ms", 0, "cancel Connect after this delay; fault-check only")
	cancelStage := flag.String("cancel-stage", "", "fault-check: adapter or routes")
	out := flag.String("out", "netbench.jsonl", "report")
	flag.Parse()
	exe, _ := os.Executable()
	dir := filepath.Dir(exe)
	dataDir := filepath.Join(os.Getenv("APPDATA"), "csqtt")
	b, e := os.ReadFile(filepath.Join(dataDir, "config.json"))
	if e != nil {
		panic("read configuration failed")
	}
	var cfg core.Config
	if json.Unmarshal(b, &cfg) != nil {
		panic("invalid configuration")
	}
	id, e := os.ReadFile(filepath.Join(dataDir, "device-id"))
	if e != nil {
		panic("device ID missing")
	}
	cfg.DeviceID = strings.TrimSpace(string(id))
	cfg.SystemVPN = true
	f, e := os.OpenFile(*out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		panic(e)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for i := 1; i <= *n; i++ {
		start := time.Now()
		row := map[string]any{"cycle": i, "workers": cfg.Workers}
		var mu sync.Mutex
		var assignedIP net.IP
		var cancelConnect context.CancelFunc
		mgr := core.NewManager(filepath.Join(dir, "bin"), filepath.Join(os.TempDir(), "csqtt"), func(s string) {
			if strings.HasPrefix(s, "✅ CSQTT system VPN активен: ") {
				value := strings.SplitN(strings.TrimPrefix(s, "✅ CSQTT system VPN активен: "), ",", 2)[0]
				mu.Lock()
				assignedIP = net.ParseIP(value)
				mu.Unlock()
			}
			if (*cancelStage == "adapter" && strings.HasPrefix(s, "✓ Адаптер Wintun")) || (*cancelStage == "routes" && strings.HasPrefix(s, "✓ Системные маршруты направлены")) {
				mu.Lock()
				row["cancel_stage_reached"] = *cancelStage
				mu.Unlock()
				cancelConnect()
			}
			if strings.HasPrefix(s, "[STARTUP]") {
				mu.Lock()
				row[s] = time.Since(start).Seconds()
				mu.Unlock()
			}
		}, func(string, string, string) string { return "" })
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
		cancelConnect = cancel
		var timer *time.Timer
		if *cancelMS > 0 {
			timer = time.AfterFunc(time.Duration(*cancelMS)*time.Millisecond, cancel)
		}
		err := mgr.Connect(ctx, cfg)
		if timer != nil {
			timer.Stop()
		}
		mu.Lock()
		row["routing_seconds"] = time.Since(start).Seconds()
		row["connected"] = err == nil
		row["canceled"] = errors.Is(err, context.Canceled)
		row["context_canceled"] = ctx.Err() != nil
		mu.Unlock()
		if err == nil {
			mu.Lock()
			ip := assignedIP
			mu.Unlock()
			iface, _ := net.InterfaceByName("CSQTT")
			if iface != nil {
				as, _ := iface.Addrs()
				var values []string
				for _, a := range as {
					values = append(values, a.String())
				}
				mu.Lock()
				row["tun_addresses"] = values
				row["probe_ip"] = ip.String()
				mu.Unlock()
			}
			if ip != nil {
				q := new(dns.Msg)
				q.SetQuestion("example.com.", dns.TypeA)
				dc := dns.Client{Timeout: 5 * time.Second}
				res, _, de := dc.Exchange(q, net.JoinHostPort(ip.String(), "53"))
				mu.Lock()
				row["dns_ok"] = de == nil && res != nil && res.Rcode == 0 && len(res.Answer) > 0
				row["dns_seconds"] = time.Since(start).Seconds()
				row["dns_error_type"] = fmt.Sprintf("%T", de)
				mu.Unlock()
				d := net.Dialer{Timeout: 6 * time.Second, LocalAddr: &net.TCPAddr{IP: ip}}
				tr := &http.Transport{DialContext: d.DialContext}
				hc := http.Client{Transport: tr, Timeout: 8 * time.Second}
				resp, he := hc.Get("https://1.1.1.1/cdn-cgi/trace")
				ok := he == nil && resp.StatusCode == 200
				if resp != nil {
					resp.Body.Close()
				}
				tr.CloseIdleConnections()
				mu.Lock()
				row["https_ok"] = ok
				row["https_seconds"] = time.Since(start).Seconds()
				row["https_error_type"] = fmt.Sprintf("%T", he)
				mu.Unlock()
			}
		}
		stop := time.Now()
		cancel()
		cleanCtx, cc := context.WithTimeout(context.Background(), 30*time.Second)
		ce := mgr.DisconnectForUpdate(cleanCtx)
		cc()
		mu.Lock()
		row["cleanup_seconds"] = time.Since(stop).Seconds()
		row["cleanup_ok"] = ce == nil
		enc.Encode(row)
		mu.Unlock()
		f.Sync()
		fmt.Printf("cycle=%d connected=%t cleanup=%t\n", i, err == nil, ce == nil)
		if ce != nil || err != nil || row["dns_ok"] != true || row["https_ok"] != true {
			break
		}
		time.Sleep(3 * time.Second)
	}
}
