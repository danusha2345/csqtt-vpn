package updater

import (
	"archive/zip"
	"crypto/sha256"
	"debug/pe"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var BundleFiles = []string{"CSQTT-VPN.exe", "bin/csqtt-client.exe", "wintun.dll", "README.txt", "LICENSE"}

func regular(path string) error {
	i, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if !i.Mode().IsRegular() {
		return fmt.Errorf("не обычный файл: %s", path)
	}
	return nil
}
func CheckDirectory(dir string) error {
	abs, e := filepath.Abs(dir)
	if e != nil {
		return e
	}
	for p := abs; ; p = filepath.Dir(p) {
		i, e := os.Lstat(p)
		if e != nil {
			return e
		}
		if !i.IsDir() || i.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("небезопасный каталог: %s", p)
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return platformDirectoryCheck(abs)
}
func copyFile(src, dst string) (err error) {
	if err = regular(src); err != nil {
		return err
	}
	in, e := os.Open(src)
	if e != nil {
		return e
	}
	defer in.Close()
	out, e := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if e != nil {
		return e
	}
	defer func() {
		out.Close()
		if err != nil {
			os.Remove(dst)
		}
	}()
	if _, err = io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}
func Extract(archive, dir string) error {
	z, e := zip.OpenReader(archive)
	if e != nil {
		return e
	}
	defer z.Close()
	allowed := map[string]bool{}
	for _, n := range BundleFiles {
		allowed[n] = true
	}
	seen := map[string]bool{}
	var total uint64
	for _, f := range z.File {
		// Exact allowlist also rejects traversal, ADS, drive/UNC paths, case aliases and links.
		if f.Name == "bin/" && f.FileInfo().IsDir() {
			if seen[f.Name] {
				return fmt.Errorf("дубликат ZIP записи: %s", f.Name)
			}
			seen[f.Name] = true
			continue
		}
		if !allowed[f.Name] || seen[f.Name] || !f.Mode().IsRegular() {
			return fmt.Errorf("недопустимая ZIP запись: %q", f.Name)
		}
		seen[f.Name] = true
		total += f.UncompressedSize64
		if total > 512<<20 || f.UncompressedSize64 > 256<<20 {
			return fmt.Errorf("слишком большой bundle")
		}
	}
	for _, n := range BundleFiles[:3] {
		if !seen[n] {
			return fmt.Errorf("неполный bundle: %s", n)
		}
	}
	if e = os.Mkdir(dir, 0700); e != nil {
		return e
	}
	if e = os.Mkdir(filepath.Join(dir, "bin"), 0700); e != nil {
		return e
	}
	for _, f := range z.File {
		if f.Name == "bin/" {
			continue
		}
		if e = extractFile(f, filepath.Join(dir, filepath.FromSlash(f.Name))); e != nil {
			return e
		}
	}
	return ValidatePE(dir)
}
func extractFile(f *zip.File, path string) (err error) {
	r, e := f.Open()
	if e != nil {
		return e
	}
	defer r.Close()
	w, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if e != nil {
		return e
	}
	defer w.Close()
	n, e := io.Copy(w, io.LimitReader(r, int64(f.UncompressedSize64)+1))
	if e != nil {
		return e
	}
	if n != int64(f.UncompressedSize64) {
		return fmt.Errorf("размер ZIP записи не совпадает")
	}
	return w.Sync()
}
func ValidatePE(dir string) error {
	for _, n := range BundleFiles[:3] {
		p := filepath.Join(dir, filepath.FromSlash(n))
		if e := regular(p); e != nil {
			return e
		}
		f, e := pe.Open(p)
		if e != nil {
			return e
		}
		machine, flags := f.Machine, f.Characteristics
		f.Close()
		if machine != pe.IMAGE_FILE_MACHINE_AMD64 || flags&pe.IMAGE_FILE_EXECUTABLE_IMAGE == 0 || (flags&pe.IMAGE_FILE_DLL != 0) != (n == "wintun.dll") {
			return fmt.Errorf("неподходящий Windows amd64 PE: %s", n)
		}
	}
	return nil
}
func HashFile(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Transaction сохраняет старые файлы ДО первой замены. Backup остаётся до подтверждения GUI.
type Transaction struct {
	Install  string
	Stage    string
	Files    []string
	Existing map[string]bool
}

func Prepare(install, stage string) (*Transaction, error) {
	if e := CheckDirectory(install); e != nil {
		return nil, e
	}
	if e := CheckDirectory(filepath.Join(install, "bin")); e != nil {
		return nil, e
	}
	t := &Transaction{Install: install, Stage: stage, Existing: map[string]bool{}}
	backup := filepath.Join(stage, "backup")
	if e := os.Mkdir(backup, 0700); e != nil {
		return nil, e
	}
	if e := os.Mkdir(filepath.Join(backup, "bin"), 0700); e != nil {
		return nil, e
	}
	for _, n := range BundleFiles {
		src := filepath.Join(stage, "new", filepath.FromSlash(n))
		if _, e := os.Stat(src); os.IsNotExist(e) {
			continue
		}
		dst := filepath.Join(install, filepath.FromSlash(n))
		if e := regular(src); e != nil {
			return nil, e
		}
		if _, e := os.Lstat(dst); e == nil {
			if e = copyFile(dst, filepath.Join(backup, filepath.FromSlash(n))); e != nil {
				return nil, e
			}
			t.Existing[n] = true
		} else if !os.IsNotExist(e) {
			return nil, e
		}
		t.Files = append(t.Files, n)
	}
	data, e := json.Marshal(t)
	if e != nil {
		return nil, e
	}
	f, e := os.OpenFile(filepath.Join(stage, "transaction.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	if _, e = f.Write(data); e != nil {
		return nil, e
	}
	if e = f.Sync(); e != nil {
		return nil, e
	}
	return t, nil
}
func retryRename(src, dst string) error {
	var e error
	for i := 0; i < 30; i++ {
		if e = os.Rename(src, dst); e == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return e
}
func (t *Transaction) Apply() error { return t.apply(retryRename) }
func (t *Transaction) apply(move func(string, string) error) error {
	for _, n := range t.Files {
		if e := installPermissions(filepath.Join(t.Stage, "new", filepath.FromSlash(n))); e != nil {
			return e
		}
		if e := move(filepath.Join(t.Stage, "new", filepath.FromSlash(n)), filepath.Join(t.Install, filepath.FromSlash(n))); e != nil {
			return fmt.Errorf("замена %s: %w", n, e)
		}
	}
	return nil
}
func (t *Transaction) Rollback() error {
	var errors []string
	for _, n := range t.Files {
		dst := filepath.Join(t.Install, filepath.FromSlash(n))
		if t.Existing[n] {
			temp := filepath.Join(t.Stage, "restore-"+strings.ReplaceAll(n, "/", "_"))
			os.Remove(temp)
			if e := copyFile(filepath.Join(t.Stage, "backup", filepath.FromSlash(n)), temp); e != nil {
				errors = append(errors, e.Error())
				continue
			}
			if e := installPermissions(temp); e != nil {
				errors = append(errors, e.Error())
				continue
			}
			if e := retryRename(temp, dst); e != nil {
				errors = append(errors, e.Error())
			}
		} else if e := os.Remove(dst); e != nil && !os.IsNotExist(e) {
			errors = append(errors, e.Error())
		}
	}
	if len(errors) > 0 {
		return fmt.Errorf("rollback: %s", strings.Join(errors, "; "))
	}
	return nil
}
