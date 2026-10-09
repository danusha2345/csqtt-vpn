package updater

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mirrorFixture(source, version string, payload []byte) map[string][]byte {
	archive := asset("CSQTT-VPN-"+version+"-windows-amd64.zip", payload)
	infoName, sumsName := "BUILDINFO-"+version+".json", "SHA256SUMS-desktop-"+version+".txt"
	info, _ := json.Marshal(map[string]any{"version": version, "sha256": map[string]string{archive.Name: strings.TrimPrefix(archive.Digest, "sha256:")}, "sizes": map[string]int64{archive.Name: archive.Size}, "compatibility": map[string]string{"serverFork": "danusha2345/csqtt-android", "socks5": "CSQPX2"}})
	infoAsset := asset(infoName, info)
	sums := []byte(strings.TrimPrefix(archive.Digest, "sha256:") + "  " + archive.Name + "\n" + strings.TrimPrefix(infoAsset.Digest, "sha256:") + "  " + infoName + "\n")
	assets := []Asset{{Name: archive.Name}, {Name: infoName}, {Name: sumsName}}
	var value any = assets
	endpoint := "https://git.danik2files.ru/api/v1/repos/danik/csqtt-desktop/releases"
	listURL, tagURL := endpoint+"?limit=30", endpoint+"/tags/v"+version
	if source == "GitLab" {
		value = map[string]any{"links": assets}
		endpoint = "https://gitlab.com/api/v4/projects/pipecpriam%2Fcsqtt-vpn/releases"
		listURL, tagURL = endpoint+"?per_page=30", endpoint+"/v"+version
	}
	r := map[string]any{"tag_name": "v" + version, "assets": value}
	release, _ := json.Marshal(r)
	list, _ := json.Marshal([]any{r})
	return map[string][]byte{listURL: list, tagURL: release,
		sourceAssetURL(source, "v"+version, archive.Name): payload,
		sourceAssetURL(source, "v"+version, infoName):     info,
		sourceAssetURL(source, "v"+version, sumsName):     sums}
}

func TestCheckMirrorFallback(t *testing.T) {
	for _, source := range []string{"GitLab", "Forgejo"} {
		t.Run(source, func(t *testing.T) {
			fixtures := mirrorFixture(source, "2.1.19", []byte("bundle"))
			var attempted []string
			withHTTP(t, func(r *http.Request) (*http.Response, error) {
				attempted = append(attempted, r.URL.String())
				if data, ok := fixtures[r.URL.String()]; ok {
					return response(data), nil
				}
				return nil, errors.New("offline")
			})
			c, e := Check(context.Background(), "2.1.18")
			if e != nil || c.Source != source || c.Version != "2.1.19" {
				t.Fatalf("%+v %v", c, e)
			}
			if !strings.Contains(attempted[0], "api.github.com") {
				t.Fatal(attempted)
			}
			c, e = Check(context.Background(), "2.1.19")
			if e != nil || c != nil {
				t.Fatalf("current version: %+v %v", c, e)
			}
		})
	}
}

func TestDownloadMirrorKeepsExactVersionAndDigest(t *testing.T) {
	for _, source := range []string{"GitLab", "Forgejo"} {
		for _, changed := range []bool{false, true} {
			t.Run(source+map[bool]string{false: "/valid", true: "/changed"}[changed], func(t *testing.T) {
				original := []byte("correct bundle")
				payload := original
				if changed {
					payload = []byte("another bundle")
				}
				fixtures := mirrorFixture(source, "2.1.19", payload)
				withHTTP(t, func(r *http.Request) (*http.Response, error) {
					if strings.Contains(r.URL.String(), "?limit=") || strings.Contains(r.URL.String(), "?per_page=") {
						t.Fatal("download must not select latest")
					}
					if data, ok := fixtures[r.URL.String()]; ok {
						return response(data), nil
					}
					return nil, errors.New("offline")
				})
				destination := filepath.Join(t.TempDir(), "bundle.zip")
				err := Download(context.Background(), Candidate{Version: "2.1.19", Source: "GitHub", Archive: asset("CSQTT-VPN-2.1.19-windows-amd64.zip", original)}, destination, nil)
				if changed {
					if err == nil {
						t.Fatal("accepted changed mirror")
					}
					if _, e := os.Stat(destination); !os.IsNotExist(e) {
						t.Fatal("partial remains")
					}
				} else {
					if err != nil {
						t.Fatal(err)
					}
					got, _ := os.ReadFile(destination)
					if string(got) != string(original) {
						t.Fatal("wrong bytes")
					}
				}
			})
		}
	}
}

func TestMirrorMetadataFailures(t *testing.T) {
	for _, mode := range []string{"hash", "duplicate", "missing", "prerelease", "wrong-version"} {
		t.Run(mode, func(t *testing.T) {
			source, version := "GitLab", "2.1.19"
			fixtures := mirrorFixture(source, version, []byte("zip"))
			sumsURL := sourceAssetURL(source, "v"+version, "SHA256SUMS-desktop-"+version+".txt")
			infoURL := sourceAssetURL(source, "v"+version, "BUILDINFO-"+version+".json")
			switch mode {
			case "hash":
				fixtures[infoURL] = []byte("corrupt")
			case "duplicate":
				fixtures[sumsURL] = append(fixtures[sumsURL], fixtures[sumsURL]...)
			case "missing":
				delete(fixtures, sumsURL)
			case "prerelease", "wrong-version":
				endpoint := "https://gitlab.com/api/v4/projects/pipecpriam%2Fcsqtt-vpn/releases/v" + version
				var release map[string]any
				json.Unmarshal(fixtures[endpoint], &release)
				if mode == "prerelease" {
					release["upcoming_release"] = true
				} else {
					release["tag_name"] = "v2.1.20"
				}
				fixtures[endpoint], _ = json.Marshal(release)
			}
			withHTTP(t, func(r *http.Request) (*http.Response, error) {
				if b, ok := fixtures[r.URL.String()]; ok {
					return response(b), nil
				}
				return nil, errors.New("offline")
			})
			if _, err := checkMirror(context.Background(), source, "", version); err == nil {
				t.Fatal("accepted invalid mirror")
			}
		})
	}
}

func TestCancelledCheckDoesNotContactMirrors(t *testing.T) {
	withHTTP(t, func(*http.Request) (*http.Response, error) { t.Fatal("request after cancel"); return nil, nil })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Check(ctx, "2.1.18"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
