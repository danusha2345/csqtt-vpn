package updater

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{{"2.1.12", "2.1.11", true}, {"2.10.0", "2.9.99", true}, {"2.1.11", "2.1.11", false}, {"2.1.10", "2.1.11", false}, {"2.1.12-rc1", "2.1.11", false}, {"999999999999.0.0", "2.1.11", false}, {"2.1.12/evil", "2.1.11", false}} {
		if Newer(c.a, c.b) != c.want {
			t.Errorf("%+v", c)
		}
	}
}
func TestSourcePolicy(t *testing.T) {
	for _, raw := range []string{"http://github.com/x", "https://github.com.evil/x", "https://evil/github.com", "https://user@github.com/x", "https://github.com:443/x", "file:///x"} {
		u, _ := url.Parse(raw)
		if allowedURL(u) {
			t.Errorf("allowed %s", raw)
		}
	}
	for _, host := range []string{"github.com", "api.github.com", "release-assets.githubusercontent.com"} {
		u, _ := url.Parse("https://" + host + "/x")
		if !allowedURL(u) {
			t.Fatal(host)
		}
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func withHTTP(t *testing.T, f roundTrip) {
	t.Helper()
	old := http.DefaultTransport
	http.DefaultTransport = f
	t.Cleanup(func() { http.DefaultTransport = old })
}
func response(b []byte) *http.Response {
	return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(b)), Header: make(http.Header)}
}
func asset(name string, b []byte) Asset {
	h := sha256.Sum256(b)
	return Asset{Name: name, Size: int64(len(b)), Digest: "sha256:" + hex.EncodeToString(h[:])}
}
func TestCheckContract(t *testing.T) {
	archive := asset("CSQTT-VPN-2.1.12-windows-amd64.zip", []byte("zip"))
	metadata := func(version, hash, fork string) []byte {
		b, _ := json.Marshal(map[string]any{"version": version, "sha256": map[string]string{archive.Name: hash}, "compatibility": map[string]string{"serverFork": fork, "socks5": "CSQPX2; requires 2.1.11"}})
		return b
	}
	for _, tc := range []struct {
		name, version, hash, fork string
		bad                       bool
	}{{"valid", "2.1.12", strings.TrimPrefix(archive.Digest, "sha256:"), "danusha2345/csqtt-android", false}, {"version", "2.1.11", strings.TrimPrefix(archive.Digest, "sha256:"), "danusha2345/csqtt-android", true}, {"checksum", "2.1.12", strings.Repeat("0", 64), "danusha2345/csqtt-android", true}, {"fork", "2.1.12", strings.TrimPrefix(archive.Digest, "sha256:"), "amurcanov/csqtt", true}} {
		t.Run(tc.name, func(t *testing.T) {
			info := metadata(tc.version, tc.hash, tc.fork)
			r := Release{Tag: "v2.1.12", Assets: []Asset{archive, asset("BUILDINFO-2.1.12.json", info)}}
			release, _ := json.Marshal(r)
			withHTTP(t, func(req *http.Request) (*http.Response, error) {
				switch req.URL.String() {
				case "https://api.github.com/repos/" + Repository + "/releases/latest":
					return response(release), nil
				case assetURL("v2.1.12", "BUILDINFO-2.1.12.json"):
					return response(info), nil
				default:
					t.Fatalf("unexpected URL %s", req.URL)
					return nil, nil
				}
			})
			c, e := Check(context.Background(), "2.1.11")
			if (e != nil) != tc.bad {
				t.Fatalf("candidate=%+v err=%v", c, e)
			}
		})
	}
}
func TestAssetContract(t *testing.T) {
	a := asset("x", []byte("a"))
	for _, list := range [][]Asset{nil, {a, a}, {{Name: "x", Size: 1, Digest: "bad"}}, {{Name: "x", Size: MaxArchive + 1, Digest: a.Digest}}} {
		r := Release{Assets: list}
		if _, e := r.asset("x", MaxArchive); e == nil {
			t.Fatal(list)
		}
	}
}
func TestDownloadFailuresRemovePartial(t *testing.T) {
	payload := []byte("test archive bytes")
	a := asset("CSQTT-VPN-2.1.12-windows-amd64.zip", payload)
	for _, mode := range []string{"ok", "truncated", "hash", "oversize", "cancel", "network"} {
		t.Run(mode, func(t *testing.T) {
			b := append([]byte{}, payload...)
			switch mode {
			case "truncated":
				b = b[:3]
			case "hash":
				b[0] ^= 1
			case "oversize":
				b = append(b, 0)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancel" {
				cancel()
			}
			withHTTP(t, func(r *http.Request) (*http.Response, error) {
				if e := r.Context().Err(); e != nil {
					return nil, e
				}
				if mode == "network" {
					return &http.Response{StatusCode: 200, Body: io.NopCloser(&brokenReader{}), Header: make(http.Header)}, nil
				}
				return response(b), nil
			})
			path := filepath.Join(t.TempDir(), "bundle.zip")
			e := Download(ctx, Candidate{Version: "2.1.12", Archive: a}, path, nil)
			if mode == "ok" {
				if e != nil {
					t.Fatal(e)
				}
			} else {
				if e == nil {
					t.Fatal("accepted")
				}
				if _, e = os.Stat(path); !os.IsNotExist(e) {
					t.Fatal("partial remains")
				}
			}
		})
	}
}

type brokenReader struct{}

func (*brokenReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func TestZIPRejectsUnsafeEntries(t *testing.T) {
	for _, name := range []string{"../outside", "/absolute", "C:/evil", "bin/../../evil", "bin\\csqtt-client.exe", "wintun.dll:stream", "WINTUN.DLL", "config.json", "bin/evil.dll"} {
		t.Run(name, func(t *testing.T) {
			var b bytes.Buffer
			w := zip.NewWriter(&b)
			f, _ := w.Create(name)
			f.Write([]byte("a"))
			w.Close()
			dir := t.TempDir()
			p := filepath.Join(dir, "b.zip")
			os.WriteFile(p, b.Bytes(), 0600)
			if e := Extract(p, filepath.Join(dir, "new")); e == nil {
				t.Fatal("accepted unsafe name")
			}
		})
	}
}
func TestZIPRejectsSymlinkDuplicateMissingAndWrongPE(t *testing.T) {
	for _, mode := range []string{"link", "duplicate", "missing", "wrongPE"} {
		t.Run(mode, func(t *testing.T) {
			var b bytes.Buffer
			w := zip.NewWriter(&b)
			for _, n := range BundleFiles[:3] {
				if mode == "missing" && n == "wintun.dll" {
					continue
				}
				h := &zip.FileHeader{Name: n, Method: zip.Store}
				h.SetMode(0600)
				if mode == "link" {
					h.SetMode(os.ModeSymlink | 0700)
				}
				f, _ := w.CreateHeader(h)
				f.Write([]byte("invalid PE"))
			}
			if mode == "duplicate" {
				w.Create("wintun.dll")
			}
			w.Close()
			d := t.TempDir()
			p := filepath.Join(d, "b.zip")
			os.WriteFile(p, b.Bytes(), 0600)
			if e := Extract(p, filepath.Join(d, "new")); e == nil {
				t.Fatal("accepted")
			}
		})
	}
}
func TestRollbackAfterEachReplacementFailure(t *testing.T) {
	for fail := 0; fail < len(BundleFiles); fail++ {
		t.Run(BundleFiles[fail], func(t *testing.T) {
			d := t.TempDir()
			install := filepath.Join(d, "install")
			stage := filepath.Join(d, "stage")
			os.MkdirAll(filepath.Join(install, "bin"), 0700)
			os.MkdirAll(filepath.Join(stage, "new", "bin"), 0700)
			for _, n := range BundleFiles {
				os.WriteFile(filepath.Join(stage, "new", n), []byte("new "+n), 0700)
				if n != "README.txt" {
					os.WriteFile(filepath.Join(install, n), []byte("old "+n), 0700)
				}
			}
			os.WriteFile(filepath.Join(install, "profile.json"), []byte("preserve"), 0600)
			tx, e := Prepare(install, stage)
			if e != nil {
				t.Fatal(e)
			}
			i := 0
			e = tx.apply(func(a, b string) error {
				defer func() { i++ }()
				if i == fail {
					return errors.New("locked EXE")
				}
				return os.Rename(a, b)
			})
			if e == nil {
				t.Fatal("wanted failure")
			}
			if e = tx.Rollback(); e != nil {
				t.Fatal(e)
			}
			for _, n := range BundleFiles {
				b, e := os.ReadFile(filepath.Join(install, n))
				if n == "README.txt" {
					if !os.IsNotExist(e) {
						t.Fatal("new optional file survived")
					}
				} else if e != nil || string(b) != "old "+n {
					t.Fatalf("rollback %s: %s %v", n, b, e)
				}
			}
			b, _ := os.ReadFile(filepath.Join(install, "profile.json"))
			if string(b) != "preserve" {
				t.Fatal("profile changed")
			}
			// Rollback is repeatable: backups were copied, never consumed.
			if e = tx.Rollback(); e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestPrepareRejectsSymlink(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "link")
	if e := os.Symlink(d, p); e != nil {
		t.Skip(e)
	}
	if e := CheckDirectory(p); e == nil {
		t.Fatal("accepted symlink")
	}
}
