package core

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestExtractVKToken(t *testing.T) {
	cases := map[string]string{
		"  vk1.a.raw  ": "vk1.a.raw",
		"https://oauth.vk.ru/blank.html#access_token=vk1.a.XYZ&expires_in=0&user_id=1": "vk1.a.XYZ",
		"https://oauth.vk.ru/blank.html#expires_in=0&access_token=abc%2Ddef":           "abc-def",
	}
	for in, want := range cases {
		if got := ExtractVKToken(in); got != want {
			t.Fatalf("ExtractVKToken(%q)=%q want %q", in, got, want)
		}
	}
}

func TestNormalizeVKHashMode(t *testing.T) {
	for in, want := range map[string]string{"": VKHashManual, "AUTO": VKHashAutoAPI, "auto_api": VKHashAutoAPI, "auto_js": VKHashAutoJS, "x": VKHashManual} {
		if got := NormalizeVKHashMode(in); got != want {
			t.Fatalf("mode(%q)=%q want %q", in, got, want)
		}
	}
}

func TestVKCallCountForWorkers(t *testing.T) {
	for workers, want := range map[int]int{9: 1, 18: 1, 27: 1, 36: 2, 54: 2, 63: 3, 126: 5, 0: 1} {
		if got := vkCallCountForWorkers(workers); got != want {
			t.Fatalf("workers=%d calls=%d want %d", workers, got, want)
		}
	}
}

func TestAutoAPICallsLifecycle(t *testing.T) {
	var mu sync.Mutex
	started, finished := 0, map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			fmt.Fprint(w, `{"error":{"error_code":5,"error_msg":"auth"}}`)
			return
		}
		_ = r.ParseForm()
		mu.Lock()
		defer mu.Unlock()
		switch {
		case strings.HasSuffix(r.URL.Path, "/calls.start"):
			started++
			fmt.Fprintf(w, `{"response":{"call_id":"c%d","join_link":"https://vk.com/call/join/h%d"}}`, started, started)
		case strings.HasSuffix(r.URL.Path, "/calls.forceFinish"):
			finished[r.Form.Get("call_id")] = true
			fmt.Fprint(w, `{"response":1}`)
		}
	}))
	defer srv.Close()
	old := vkAPIBase
	vkAPIBase = srv.URL + "/method/"
	defer func() { vkAPIBase = old }()

	m := NewManager(t.TempDir(), t.TempDir(), nil, nil)
	hashes, err := m.startVKCalls(context.Background(), "tok", 36)
	if err != nil || strings.Join(hashes, ",") != "h1,h2" {
		t.Fatalf("hashes=%v err=%v", hashes, err)
	}
	if _, err := os.Stat(m.vkStatePath()); err != nil {
		t.Fatalf("state not persisted: %v", err)
	}
	// Новый менеджер (как после падения GUI) должен завершить звонки с диска.
	restarted := NewManager(t.TempDir(), m.runDir, nil, nil)
	if err := restarted.finishVKCalls(false); err != nil {
		t.Fatal(err)
	}
	if !finished["c1"] || !finished["c2"] {
		t.Fatalf("finished=%v", finished)
	}
	if _, err := os.Stat(m.vkStatePath()); !os.IsNotExist(err) {
		t.Fatalf("state not removed: %v", err)
	}

	if _, err := m.startVKCalls(context.Background(), "bad", 18); err == nil || !strings.Contains(err.Error(), "недействителен") {
		t.Fatalf("invalid token err=%v", err)
	}
}

func TestStopClientSendsFinishBeforeStop(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("нужен sh")
	}
	out := filepath.Join(t.TempDir(), "stdin")
	cmd := exec.Command("sh", "-c", `cat > "$0"`, out)
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exit := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exit) }()
	m := NewManager(t.TempDir(), t.TempDir(), nil, nil)
	m.stopClient(cmd, input, exit, VKHashAutoJS, 5*time.Second)
	select {
	case <-exit:
	default:
		t.Fatal("клиент не завершён")
	}
	data, _ := os.ReadFile(out)
	if string(data) != "FINISH_VK_CALLS\nSTOP\n" {
		t.Fatalf("stdin=%q", data)
	}
}
