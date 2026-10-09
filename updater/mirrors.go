package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

var sources = []string{"GitHub", "GitLab", "Forgejo"}

func sourceAssetURL(source, tag, name string) string {
	switch source {
	case "", "GitHub":
		return assetURL(tag, name)
	case "GitLab":
		return "https://gitlab.com/pipecpriam/csqtt-vpn/-/releases/" + tag + "/downloads/" + name
	case "Forgejo":
		return "https://git.danik2files.ru/danik/csqtt-desktop/releases/download/" + tag + "/" + name
	}
	return ""
}

func Check(ctx context.Context, current string) (*Candidate, error) {
	var failures []error
	for _, source := range sources {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		attempt, cancel := context.WithTimeout(ctx, 25*time.Second)
		var candidate *Candidate
		var err error
		if source == "GitHub" {
			candidate, err = checkGitHub(attempt, current)
		} else {
			candidate, err = checkMirror(attempt, source, current, "")
		}
		cancel()
		if err == nil {
			return candidate, nil
		}
		failures = append(failures, fmt.Errorf("%s: %w", source, err))
	}
	return nil, errors.Join(failures...)
}

func boundedGet(ctx context.Context, link string, limit int64) ([]byte, error) {
	resp, err := request(ctx, link)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("ответ источника слишком большой")
	}
	return data, nil
}

func parseChecksums(data []byte) (map[string]string, error) {
	sums := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 2 {
			return nil, fmt.Errorf("неверный SHA256SUMS")
		}
		hash, err := digest(Asset{Name: fields[1], Digest: "sha256:" + fields[0]})
		if err != nil {
			return nil, err
		}
		name := strings.TrimPrefix(fields[1], "*")
		if _, exists := sums[name]; exists {
			return nil, fmt.Errorf("повтор имени в SHA256SUMS")
		}
		sums[name] = hash
	}
	return sums, nil
}

type mirrorRelease struct {
	Tag         string          `json:"tag_name"`
	Notes       string          `json:"body"`
	Description string          `json:"description"`
	Draft       bool            `json:"draft"`
	Prerelease  bool            `json:"prerelease"`
	Upcoming    bool            `json:"upcoming_release"`
	Assets      json.RawMessage `json:"assets"`
}

func (r mirrorRelease) stable() bool {
	return !r.Draft && !r.Prerelease && !r.Upcoming && strings.HasPrefix(r.Tag, "v") && versionPattern.MatchString(strings.TrimPrefix(r.Tag, "v"))
}

func checkMirror(ctx context.Context, source, current, exact string) (*Candidate, error) {
	var endpoint string
	switch source {
	case "GitLab":
		endpoint = "https://gitlab.com/api/v4/projects/pipecpriam%2Fcsqtt-vpn/releases"
	case "Forgejo":
		endpoint = "https://git.danik2files.ru/api/v1/repos/danik/csqtt-desktop/releases"
	default:
		return nil, fmt.Errorf("неизвестное зеркало")
	}
	if exact != "" {
		if !versionPattern.MatchString(exact) {
			return nil, fmt.Errorf("неверная версия")
		}
		if source == "Forgejo" {
			endpoint += "/tags"
		}
		endpoint += "/v" + exact
	} else if source == "GitLab" {
		endpoint += "?per_page=30"
	} else {
		endpoint += "?limit=30"
	}
	data, err := boundedGet(ctx, endpoint, 2<<20)
	if err != nil {
		return nil, err
	}
	var release *mirrorRelease
	if exact != "" {
		var r mirrorRelease
		if err = json.Unmarshal(data, &r); err != nil {
			return nil, err
		}
		if r.Tag != "v"+exact || !r.stable() {
			return nil, fmt.Errorf("зеркало не подтвердило версию")
		}
		release = &r
	} else {
		var list []mirrorRelease
		if err = json.Unmarshal(data, &list); err != nil {
			return nil, err
		}
		for i := range list {
			r := &list[i]
			if r.stable() && (release == nil || Newer(strings.TrimPrefix(r.Tag, "v"), strings.TrimPrefix(release.Tag, "v"))) {
				release = r
			}
		}
		if release == nil {
			return nil, fmt.Errorf("нет стабильного релиза")
		}
	}
	version := strings.TrimPrefix(release.Tag, "v")
	if exact == "" && !Newer(version, current) {
		return nil, nil
	}
	var assets []Asset
	if source == "GitLab" {
		var a struct {
			Links []Asset `json:"links"`
		}
		if err = json.Unmarshal(release.Assets, &a); err != nil {
			return nil, err
		}
		assets = a.Links
	} else if err = json.Unmarshal(release.Assets, &assets); err != nil {
		return nil, err
	}
	zipName, infoName, sumsName := "CSQTT-VPN-"+version+"-windows-amd64.zip", "BUILDINFO-"+version+".json", "SHA256SUMS-desktop-"+version+".txt"
	var archive Asset
	for _, name := range []string{zipName, infoName, sumsName} {
		count := 0
		for _, a := range assets {
			if a.Name == name {
				count++
				if name == zipName {
					archive = a
				}
			}
		}
		if count != 1 {
			return nil, fmt.Errorf("нет единственного asset %s", name)
		}
	}
	data, err = boundedGet(ctx, sourceAssetURL(source, release.Tag, sumsName), 64<<10)
	if err != nil {
		return nil, err
	}
	sums, err := parseChecksums(data)
	if err != nil {
		return nil, err
	}
	data, err = boundedGet(ctx, sourceAssetURL(source, release.Tag, infoName), 1<<20)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(data)
	if hex.EncodeToString(hash[:]) != sums[infoName] {
		return nil, fmt.Errorf("SHA256 BUILDINFO не совпадает")
	}
	var info struct {
		Version       string            `json:"version"`
		SHA           map[string]string `json:"sha256"`
		Sizes         map[string]int64  `json:"sizes"`
		Compatibility struct {
			ServerFork string `json:"serverFork"`
			Socks5     string `json:"socks5"`
		} `json:"compatibility"`
	}
	if err = json.Unmarshal(data, &info); err != nil {
		return nil, err
	}
	archive.Digest = "sha256:" + sums[zipName]
	if _, err = digest(archive); err != nil {
		return nil, err
	}
	if info.Version != version || info.SHA[zipName] != sums[zipName] || info.Compatibility.ServerFork != "danusha2345/csqtt-android" || info.Compatibility.Socks5 == "" {
		return nil, fmt.Errorf("BUILDINFO: версия, checksum или совместимость не подтверждены")
	}
	if archive.Size == 0 {
		archive.Size = info.Sizes[zipName]
	}
	if archive.Size == 0 {
		// Старые GitLab assets не имеют размера в API/BUILDINFO.
		req, e := http.NewRequestWithContext(ctx, "HEAD", sourceAssetURL(source, release.Tag, zipName), nil)
		if e != nil {
			return nil, e
		}
		resp, e := client().Do(req)
		if e != nil {
			return nil, e
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("размер asset: HTTP %d", resp.StatusCode)
		}
		archive.Size = resp.ContentLength
	}
	if archive.Size <= 0 || archive.Size > MaxArchive {
		return nil, fmt.Errorf("некорректный размер ZIP")
	}
	notes := release.Notes
	if source == "GitLab" {
		notes = release.Description
	}
	return &Candidate{Version: version, Notes: notes, Compatibility: info.Compatibility.ServerFork + ": " + info.Compatibility.Socks5, Archive: archive, Source: source}, nil
}

// Download сохраняет исходные version/size/SHA256 при переключении зеркала.
func Download(ctx context.Context, c Candidate, path string, progress func(int64, int64)) error {
	if _, err := digest(c.Archive); err != nil {
		return err
	}
	if !versionPattern.MatchString(c.Version) || c.Archive.Name != "CSQTT-VPN-"+c.Version+"-windows-amd64.zip" || c.Archive.Size <= 0 || c.Archive.Size > MaxArchive {
		return fmt.Errorf("некорректный Windows asset")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return fmt.Errorf("путь загрузки уже существует или недоступен")
	}
	var failures []error
	if err := downloadOne(ctx, c, path, progress); err == nil {
		return nil
	} else if ctx.Err() != nil {
		return ctx.Err()
	} else {
		failures = append(failures, err)
	}
	for _, source := range sources {
		if source == c.Source || (source == "GitHub" && c.Source == "") {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		attempt, cancel := context.WithTimeout(ctx, 25*time.Second)
		var mirror *Candidate
		var err error
		if source == "GitHub" {
			mirror, err = checkGitHubTag(attempt, "0.0.0", c.Version)
		} else {
			mirror, err = checkMirror(attempt, source, "", c.Version)
		}
		cancel()
		if err == nil && mirror == nil {
			err = fmt.Errorf("зеркало не подтвердило архив")
		}
		if err == nil && (mirror.Archive.Digest != c.Archive.Digest || mirror.Archive.Size != c.Archive.Size) {
			err = fmt.Errorf("зеркало содержит другой архив")
		}
		if err == nil {
			if progress != nil {
				progress(0, mirror.Archive.Size)
			}
			err = downloadOne(ctx, *mirror, path, progress)
		}
		if err == nil {
			return nil
		}
		failures = append(failures, fmt.Errorf("%s: %w", source, err))
	}
	return fmt.Errorf("загрузка обновления не удалась: %w", errors.Join(failures...))
}
