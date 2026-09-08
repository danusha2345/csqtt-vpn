// Package updater проверяет и устанавливает Windows bundle из нашего GitHub release.
package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const Repository = "danusha2345/csqtt-vpn"
const MaxArchive = 256 << 20

var versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

type Asset struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"`
}
type Release struct {
	Tag        string  `json:"tag_name"`
	Notes      string  `json:"body"`
	Draft      bool    `json:"draft"`
	Prerelease bool    `json:"prerelease"`
	Assets     []Asset `json:"assets"`
}
type Candidate struct {
	Version       string `json:"version"`
	Notes         string `json:"notes"`
	Compatibility string `json:"compatibility"`
	Archive       Asset  `json:"-"`
}

func Newer(next, current string) bool {
	a, b := versionPattern.FindStringSubmatch(next), versionPattern.FindStringSubmatch(current)
	if a == nil || b == nil {
		return false
	}

	var av, bv [3]uint64
	for i := 1; i <= 3; i++ {
		x, e := strconv.ParseUint(a[i], 10, 32)
		y, f := strconv.ParseUint(b[i], 10, 32)
		if e != nil || f != nil {
			return false
		}
		av[i-1], bv[i-1] = x, y
	}
	for i := 0; i < 3; i++ {
		if av[i] != bv[i] {
			return av[i] > bv[i]
		}
	}

	return false
}
func digest(a Asset) (string, error) {
	s := strings.TrimPrefix(a.Digest, "sha256:")
	b, e := hex.DecodeString(s)
	if !strings.HasPrefix(a.Digest, "sha256:") || e != nil || len(b) != 32 {
		return "", fmt.Errorf("нет SHA-256 для %s", a.Name)
	}
	return strings.ToLower(s), nil
}
func (r Release) asset(name string, max int64) (Asset, error) {
	var found []Asset
	for _, a := range r.Assets {
		if a.Name == name {
			found = append(found, a)
		}
	}
	if len(found) != 1 || found[0].Size <= 0 || found[0].Size > max {
		return Asset{}, fmt.Errorf("отсутствует или некорректен asset %s", name)
	}
	_, err := digest(found[0])
	return found[0], err
}
func allowedURL(u *url.URL) bool {
	return u.Scheme == "https" && u.User == nil && u.Port() == "" && (u.Host == "api.github.com" || u.Host == "github.com" || u.Host == "release-assets.githubusercontent.com")
}
func client() *http.Client {
	return &http.Client{Timeout: 15 * time.Minute, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) >= 5 || !allowedURL(r.URL) {
			return fmt.Errorf("недопустимый redirect")
		}
		return nil
	}}
}
func request(ctx context.Context, raw string) (*http.Response, error) {
	u, err := url.Parse(raw)
	if err != nil || !allowedURL(u) {
		return nil, fmt.Errorf("недопустимый источник")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", raw, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "CSQTT-Desktop-Updater")
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client().Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		resp.Body.Close()
		return nil, fmt.Errorf("GitHub HTTP %d", resp.StatusCode)
	}
	return resp, nil
}
func assetURL(tag, name string) string {
	return "https://github.com/" + Repository + "/releases/download/" + tag + "/" + name
}
func readAsset(ctx context.Context, tag string, a Asset) ([]byte, error) {
	resp, e := request(ctx, assetURL(tag, a.Name))
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(io.LimitReader(resp.Body, a.Size+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) != a.Size {
		return nil, fmt.Errorf("размер %s не совпадает", a.Name)
	}
	sum := sha256.Sum256(b)
	want, e := digest(a)
	if e != nil || hex.EncodeToString(sum[:]) != want {
		return nil, fmt.Errorf("SHA-256 %s не совпадает", a.Name)
	}
	return b, nil
}
func Check(ctx context.Context, current string) (*Candidate, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	resp, e := request(ctx, "https://api.github.com/repos/"+Repository+"/releases/latest")
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	var r Release
	if e = json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&r); e != nil {
		return nil, e
	}
	v := strings.TrimPrefix(r.Tag, "v")
	if r.Draft || r.Prerelease || r.Tag != "v"+v || !versionPattern.MatchString(v) {
		return nil, fmt.Errorf("релиз не является стабильным semver")
	}
	if !Newer(v, current) {
		return nil, nil
	}
	a, e := r.asset("CSQTT-VPN-"+v+"-windows-amd64.zip", MaxArchive)
	if e != nil {
		return nil, e
	}
	info, e := r.asset("BUILDINFO-"+v+".json", 1<<20)
	if e != nil {
		return nil, e
	}
	data, e := readAsset(ctx, r.Tag, info)
	if e != nil {
		return nil, e
	}
	var m struct {
		Version       string            `json:"version"`
		SHA           map[string]string `json:"sha256"`
		Compatibility struct {
			ServerFork string `json:"serverFork"`
			Socks5     string `json:"socks5"`
		} `json:"compatibility"`
	}
	if e = json.Unmarshal(data, &m); e != nil {
		return nil, e
	}
	hash, _ := digest(a)
	if m.Version != v || m.SHA[a.Name] != hash || m.Compatibility.ServerFork != "danusha2345/csqtt-android" || m.Compatibility.Socks5 == "" {
		return nil, fmt.Errorf("BUILDINFO: версия, checksum или совместимость не подтверждены")
	}
	return &Candidate{Version: v, Notes: r.Notes, Compatibility: m.Compatibility.ServerFork + ": " + m.Compatibility.Socks5, Archive: a}, nil
}

// Download никогда не возобновляет непроверенный partial; при ошибке файл удаляется.
func Download(ctx context.Context, c Candidate, path string, progress func(int64, int64)) (err error) {
	want, e := digest(c.Archive)
	if e != nil {
		return e
	}
	if !versionPattern.MatchString(c.Version) || c.Archive.Name != "CSQTT-VPN-"+c.Version+"-windows-amd64.zip" || c.Archive.Size <= 0 || c.Archive.Size > MaxArchive {
		return fmt.Errorf("некорректный Windows asset")
	}
	resp, e := request(ctx, assetURL("v"+c.Version, c.Archive.Name))
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer func() {
		f.Close()
		if err != nil {
			os.Remove(path)
		}
	}()
	h := sha256.New()
	p := &progressWriter{w: io.MultiWriter(f, h), total: c.Archive.Size, report: progress}
	n, e := io.Copy(p, io.LimitReader(resp.Body, c.Archive.Size+1))
	if e != nil {
		return e
	}
	if n != c.Archive.Size || hex.EncodeToString(h.Sum(nil)) != want {
		return fmt.Errorf("размер или SHA-256 загрузки не совпадает")
	}
	return f.Sync()
}

type progressWriter struct {
	w        io.Writer
	n, total int64
	last     time.Time
	report   func(int64, int64)
}

func (p *progressWriter) Write(b []byte) (int, error) {
	n, e := p.w.Write(b)
	p.n += int64(n)
	if p.report != nil && (time.Since(p.last) > 150*time.Millisecond || p.n >= p.total) {
		p.report(p.n, p.total)
		p.last = time.Now()
	}
	return n, e
}
