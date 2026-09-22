package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Режимы источника VK-звонков — те же значения, что у Android-клиента и ядра.
const (
	VKHashManual  = "manual"
	VKHashAutoAPI = "auto_api"
	VKHashAutoJS  = "auto_js"
)

// VKOAuthURL — implicit-flow авторизация VK; после входа браузер попадает на
// oauth.vk.ru/blank.html#access_token=…, этот адрес пользователь вставляет в GUI.
const VKOAuthURL = "https://oauth.vk.ru/authorize?client_id=7793118&scope=1073737727" +
	"&redirect_uri=https%3A%2F%2Foauth.vk.ru%2Fblank.html&display=page&response_type=token&revoke=1&v=5.199"

const (
	vkAPIVersion       = "5.199"
	vkFinishTimeout    = 8 * time.Second
	vkSmallCallDelay   = 80 * time.Millisecond
	vkLargeCallDelay   = 202 * time.Millisecond
	maxVKHashes        = 6
	workersPerVKHash   = 27 // GROUPS_PER_VK_HASH(3) × WORKERS_PER_GROUP(9) в ядре
	vkCallStateFile    = "vk-calls.json"
	vkCallStateMaxSize = 64 * 1024
)

var (
	vkHTTP    = &http.Client{Timeout: 8 * time.Second}
	vkAPIBase = "https://api.vk.ru/method/" // var — подменяется в тестах
)

func NormalizeVKHashMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case VKHashAutoAPI, "auto":
		return VKHashAutoAPI
	case VKHashAutoJS:
		return VKHashAutoJS
	}
	return VKHashManual
}

var accessTokenParam = regexp.MustCompile(`access_token=([^&#\s]+)`)

// ExtractVKToken принимает и голый токен, и весь адрес blank.html#access_token=….
func ExtractVKToken(raw string) string {
	raw = strings.TrimSpace(raw)
	if match := accessTokenParam.FindStringSubmatch(raw); len(match) == 2 {
		if token, err := url.QueryUnescape(match[1]); err == nil {
			return token
		}
		return match[1]
	}
	return raw
}

// vkCallCountForWorkers повторяет VkAutoCallsManager.callCountForWorkers:
// минимум звонков, которых хватает на запрошенное число воркеров.
func vkCallCountForWorkers(workers int) int {
	workers = normalizeWorkers(workers)
	for count := 1; count <= maxVKHashes; count++ {
		if workers <= count*workersPerVKHash {
			return count
		}
	}
	return maxVKHashes
}

type vkAPIError struct {
	Code    int
	Message string
}

func (e *vkAPIError) Error() string { return fmt.Sprintf("код=%d %s", e.Code, e.Message) }

func vkTokenInvalid(err error) bool {
	var apiErr *vkAPIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.Code {
	case 4, 5, 27, 28:
		return true
	}
	return false
}

func vkRequest(ctx context.Context, method, token string, params url.Values, out any) error {
	if params == nil {
		params = url.Values{}
	}
	params.Set("v", vkAPIVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, vkAPIBase+method, strings.NewReader(params.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := vkHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	var envelope struct {
		Response json.RawMessage `json:"response"`
		Error    *struct {
			Code    int    `json:"error_code"`
			Message string `json:"error_msg"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return fmt.Errorf("ответ VK API: HTTP %d", resp.StatusCode)
	}
	if envelope.Error != nil {
		return &vkAPIError{Code: envelope.Error.Code, Message: envelope.Error.Message}
	}
	return json.Unmarshal(envelope.Response, out)
}

func vkStartCall(ctx context.Context, token string) (callID, hash string, err error) {
	var response struct {
		CallID     string `json:"call_id"`
		JoinLink   string `json:"join_link"`
		OKJoinLink string `json:"ok_join_link"`
	}
	if err := vkRequest(ctx, "calls.start", token, nil, &response); err != nil {
		return "", "", err
	}
	hash = response.OKJoinLink
	if hash == "" {
		hash = path.Base(strings.TrimRight(response.JoinLink, "/"))
	}
	if response.CallID == "" || hash == "" || hash == "." || hash == "/" {
		return "", "", fmt.Errorf("пустой call_id/hash в ответе calls.start")
	}
	return response.CallID, hash, nil
}

func vkForceFinish(ctx context.Context, token, callID string) error {
	var ignored json.RawMessage
	return vkRequest(ctx, "calls.forceFinish", token, url.Values{"call_id": {callID}}, &ignored)
}

// vkCallState — созданные нами звонки. Лежит на диске, чтобы после падения GUI
// следующий запуск завершил их, а не оставил висеть в аккаунте.
type vkCallState struct {
	Token   string   `json:"token"`
	CallIDs []string `json:"call_ids"`
}

func (m *Manager) vkStatePath() string { return filepath.Join(m.runDir, vkCallStateFile) }

// saveVKCallsLocked пишет состояние; вызывается под m.mu.
func (m *Manager) saveVKCallsLocked() {
	p := m.vkStatePath()
	if len(m.vkCalls.CallIDs) == 0 {
		_ = os.Remove(p)
		return
	}
	if data, err := json.Marshal(m.vkCalls); err == nil {
		_ = os.WriteFile(p, data, 0o600)
	}
}

// startVKCalls создаёт звонки через calls.start и возвращает их хеши.
func (m *Manager) startVKCalls(ctx context.Context, token string, workers int) ([]string, error) {
	if err := m.finishVKCalls(false); err != nil {
		return nil, fmt.Errorf("предыдущие звонки VK не завершены: %w", err)
	}
	count := vkCallCountForWorkers(workers)
	delay := vkSmallCallDelay
	if count > 4 {
		delay = vkLargeCallDelay
	}
	var hashes []string
	for i := 0; i < count; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return hashes, ctx.Err()
			case <-time.After(delay):
			}
		}
		callID, hash, err := vkStartCall(ctx, token)
		if err != nil {
			if ctx.Err() != nil {
				return hashes, ctx.Err()
			}
			m.log("⚠ Звонок VK не создан: %v", err)
			if vkTokenInvalid(err) {
				return hashes, fmt.Errorf("токен VK недействителен — получите новый")
			}
			continue
		}
		m.mu.Lock()
		m.vkCalls.Token = token
		m.vkCalls.CallIDs = append(m.vkCalls.CallIDs, callID)
		m.saveVKCallsLocked()
		m.mu.Unlock()
		hashes = append(hashes, hash)
		m.log("✅ Звонок VK создан (%d/%d)", len(hashes), count)
	}
	if len(hashes) == 0 {
		return nil, fmt.Errorf("не удалось создать ни одного звонка VK")
	}
	if len(hashes) < count {
		m.log("Звонки VK %d/%d · воркеры перераспределены", len(hashes), count)
	}
	return hashes, nil
}

// finishVKCalls завершает звонки «Авто API» — текущие и оставшиеся на диске от
// прошлого запуска. Ошибка значит, что часть звонков осталась активной.
func (m *Manager) finishVKCalls(logResults bool) error {
	m.mu.Lock()
	state := m.vkCalls
	if len(state.CallIDs) == 0 {
		if data, err := os.ReadFile(m.vkStatePath()); err == nil && len(data) <= vkCallStateMaxSize {
			_ = json.Unmarshal(data, &state)
		}
	}
	m.vkCalls = vkCallState{}
	m.mu.Unlock()
	if len(state.CallIDs) == 0 {
		_ = os.Remove(m.vkStatePath())
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), vkFinishTimeout)
	defer cancel()
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		failed []string
		errs   []error
	)
	for _, id := range state.CallIDs {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			err := vkForceFinish(ctx, state.Token, id)
			var apiErr *vkAPIError
			if err != nil && !errors.As(err, &apiErr) {
				// Сеть/таймаут: звонок, возможно, жив — оставляем для повтора.
				mu.Lock()
				failed = append(failed, id)
				errs = append(errs, err)
				mu.Unlock()
			}
			if logResults {
				if err != nil {
					m.log("⚠ Звонок VK не завершён: %v", err)
				} else {
					m.log("Звонок VK завершён")
				}
			}
		}(id)
	}
	wg.Wait()
	m.mu.Lock()
	m.vkCalls.Token = state.Token
	m.vkCalls.CallIDs = append(m.vkCalls.CallIDs, failed...)
	if len(m.vkCalls.CallIDs) == 0 {
		m.vkCalls.Token = ""
	}
	m.saveVKCallsLocked()
	m.mu.Unlock()
	return errors.Join(errs...)
}
