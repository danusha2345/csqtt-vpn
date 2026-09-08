package core

import (
	"context"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestWindowsBatchesPreserveScopeAndStrictRouteChecks(t *testing.T) {
	script := windowsCleanupScript(`C:\O'Brien\bin\csqtt-client.exe`, "CSQTT", "CSQTT DNS", "CSQTT_MANAGED")
	for _, required := range []string{"O''Brien", "ExecutablePath -eq $target", "-InterfaceAlias 'CSQTT'", "CSQTT_MANAGED", "Clear-DnsClientCache"} {
		if !strings.Contains(script, required) {
			t.Fatalf("missing cleanup constraint: %s", required)
		}
	}
	if strings.Contains(windowsCleanupScript("", "CSQTT", "CSQTT DNS", "CSQTT_MANAGED"), "Stop-Process") {
		t.Fatal("teardown kills processes")
	}
	script, err := windowsSplitScript("12")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1", "-ErrorAction Stop", "Get-NetRoute", "throw", "[ordered]"} {
		if !strings.Contains(script, required) {
			t.Fatalf("missing route guard: %s", required)
		}
	}
	for _, invalid := range []string{"0", "12;exit", "-1", "4294967296"} {
		if _, err := windowsSplitScript(invalid); err == nil {
			t.Fatal("invalid index accepted")
		}
	}
}

func TestTrafficCountersConcurrentAndFreshSession(t *testing.T) {
	var c trafficCounters
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				c.down.Add(13)
				c.up.Add(7)
				c.snapshot()
			}
		}()
	}
	wg.Wait()
	down, up := c.snapshot()
	if down != 104000 || up != 56000 {
		t.Fatalf("incorrect traffic: %d %d", down, up)
	}
	fresh := trafficCounters{}
	if down, up := fresh.snapshot(); down != 0 || up != 0 {
		t.Fatal("counters leaked into next session")
	}
}

func TestCommandCancellationAndTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := runCommandContext(ctx, time.Second, "must-not-run"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = runCommandContext(context.Background(), 100*time.Millisecond, exe, "-test.run=TestCommandSleeper", "--", "csqtt-timeout-helper")
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 3*time.Second {
		t.Fatalf("timeout not enforced: %v", err)
	}
}

func TestCommandSleeper(t *testing.T) {
	if os.Args[len(os.Args)-1] == "csqtt-timeout-helper" {
		time.Sleep(time.Minute)
	}
}

func TestDNSCacheIsBoundedAndNeverExtendsTTL(t *testing.T) {
	p := &dnsProxy{}
	reply := new(dns.Msg)
	reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}}}
	for i := 0; i < 10000; i++ {
		p.cachePut(fmt.Sprint(i), reply)
	}
	if len(p.cache) > dnsCacheEntries {
		t.Fatal("unbounded cache")
	}
	reply.Answer[0].Header().Ttl = 0
	p.cachePut("zero", reply)
	if p.cacheGet("zero") != nil {
		t.Fatal("TTL zero cached")
	}
	reply.Answer[0].Header().Ttl = 60
	p.cachePut("ttl", reply)
	e := p.cache["ttl"]
	e.expiry = time.Now().Add(20 * time.Second)
	p.cache["ttl"] = e
	if got := p.cacheGet("ttl"); got == nil || got.Answer[0].Header().Ttl > 20 {
		t.Fatal("upstream TTL extended")
	}
	e.expiry = time.Now().Add(-time.Second)
	p.cache["ttl"] = e
	if p.cacheGet("ttl") != nil {
		t.Fatal("expired entry served")
	}
}
