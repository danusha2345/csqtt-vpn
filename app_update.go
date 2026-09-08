package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"csqtt-vpn/core"
	"csqtt-vpn/updater"
	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

//go:embed wails.json
var buildConfig []byte

func desktopVersion() string {
	var c struct {
		Info struct {
			Version string `json:"productVersion"`
		} `json:"info"`
	}
	_ = json.Unmarshal(buildConfig, &c)
	return c.Info.Version
}

type updateState struct {
	mu        sync.Mutex
	candidate *updater.Candidate
	cancel    context.CancelFunc
	busy      bool
}
type VersionInfo struct {
	Desktop       string `json:"desktop"`
	Core          string `json:"core"`
	Compatibility string `json:"compatibility"`
}

func (a *App) VersionInfo() VersionInfo {
	name := "csqtt-client"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	coreVersion := bundledCoreIdentity(filepath.Join(binDir(), name))
	return VersionInfo{desktopVersion(), coreVersion, "danusha2345/csqtt-android 2.1.11; CSQPX2. Upstream amurcanov/csqtt 2.1.9 несовместим."}
}
func (a *App) UpdateReady() { updater.Acknowledge(desktopVersion()) }
func (a *App) CheckForUpdate() (*updater.Candidate, error) {
	if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
		return nil, fmt.Errorf("обновления доступны для Windows amd64")
	}

	a.update.mu.Lock()
	if a.update.busy {
		a.update.mu.Unlock()
		return nil, fmt.Errorf("обновление уже выполняется")
	}
	ctx, cancel := context.WithCancel(a.ctx)
	a.update.busy = true
	a.update.cancel = cancel
	a.update.candidate = nil
	a.update.mu.Unlock()
	c, e := updater.Check(ctx, desktopVersion())
	cancel()
	a.update.mu.Lock()
	a.update.busy = false
	a.update.cancel = nil
	if e == nil {
		a.update.candidate = c
	}
	a.update.mu.Unlock()
	return c, e
}

func (a *App) CancelUpdate() {
	a.update.mu.Lock()
	defer a.update.mu.Unlock()
	if a.update.cancel != nil {
		a.update.cancel()
	}
}
func (a *App) InstallUpdate() (err error) {
	a.mu.Lock()
	closing := a.closing
	a.mu.Unlock()
	if closing {
		return fmt.Errorf("приложение закрывается")
	}
	a.update.mu.Lock()
	if a.update.busy || a.update.candidate == nil {
		a.update.mu.Unlock()
		return fmt.Errorf("сначала проверьте обновления")
	}
	c := *a.update.candidate
	ctx, cancel := context.WithCancel(a.ctx)
	a.update.cancel = cancel
	a.update.busy = true
	a.update.mu.Unlock()
	defer func() {
		cancel()
		a.update.mu.Lock()
		a.update.cancel = nil
		a.update.busy = false
		a.update.mu.Unlock()
	}()
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	install := filepath.Dir(exe)
	stage, e := updater.NewStage(install)
	if e != nil {
		return e
	}
	launched := false
	defer func() {
		if !launched {
			os.RemoveAll(stage)
		}
	}()
	progress := func(n, total int64) {
		wailsruntime.EventsEmit(a.ctx, "update-progress", map[string]int64{"received": n, "total": total})
	}
	if e = updater.Download(ctx, c, filepath.Join(stage, "bundle.zip"), progress); e != nil {
		return e
	}
	if e = updater.Extract(filepath.Join(stage, "bundle.zip"), filepath.Join(stage, "new")); e != nil {
		return e
	}
	hash, e := updater.HashFile(filepath.Join(stage, "bundle.zip"))
	if e != nil {
		return e
	}
	if e = updater.WriteTicket(stage, c.Version, hash); e != nil {
		return e
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	a.lifecycle.Lock()
	defer a.lifecycle.Unlock()
	// Блокируем новые подключения до конца установки; настройки остаются в AppData.
	a.mu.Lock()
	if a.closing {
		a.mu.Unlock()
		return fmt.Errorf("приложение закрывается")
	}
	a.updating = true
	mgr, stop, done := a.mgr, a.cancel, a.done
	a.mu.Unlock()
	defer func() {
		if !launched {
			a.mu.Lock()
			a.updating = false
			a.mu.Unlock()
		}
	}()
	if stop != nil {
		stop()
	}
	if done != nil {
		select {
		case <-done:
		case <-time.After(stopTimeout):
			return fmt.Errorf("Connect не завершился; установка отменена")
		}
	}
	if mgr != nil {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 90*time.Second)
		e = mgr.DisconnectForUpdate(stopCtx)
		stopCancel()
		if e != nil {
			return e
		}
	}
	if mgr == nil {
		checkCtx, checkCancel := context.WithTimeout(context.Background(), 30*time.Second)
		e = core.VerifyUpdateCleanup(checkCtx)
		checkCancel()
		if e != nil {
			return e
		}
	}
	a.mu.Lock()
	a.mgr = nil
	a.cancel = nil
	a.done = nil
	a.connected = false
	a.mu.Unlock()
	a.emitStatus("disconnected")
	if e = ctx.Err(); e != nil {
		return e
	}
	if e = updater.LaunchHelper(install, stage); e != nil {
		return e
	}
	launched = true
	wailsruntime.Quit(a.ctx)
	return nil
}

func (a *App) LastUpdateResult() string {
	exe, e := os.Executable()
	if e != nil {
		return ""
	}
	return updater.LastResult(filepath.Dir(exe))
}
