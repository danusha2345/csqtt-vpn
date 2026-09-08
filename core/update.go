package core

import (
	"context"
	"fmt"
)

// DisconnectForUpdate ждёт Wait процесса и подтверждает очистку перед заменой EXE.
// Вызывается только после завершения горутины Connect.
func (m *Manager) DisconnectForUpdate(ctx context.Context) error {
	m.mu.Lock()
	exit := m.exitCh
	routes := append([]string(nil), m.cleanupRoutes...)
	for r := range m.routes {
		routes = append(routes, r)
	}
	physIf := m.physIf
	if physIf == "" {
		physIf = m.cleanupPhysIf
	}
	m.mu.Unlock()
	m.Disconnect()
	m.mu.Lock()
	routes = append(routes, m.cleanupRoutes...)
	if physIf == "" {
		physIf = m.cleanupPhysIf
	}
	m.mu.Unlock()
	if exit != nil {
		select {
		case <-exit:
		case <-ctx.Done():
			return fmt.Errorf("core не завершился: %w", ctx.Err())
		}
	}
	return verifyUpdateCleanup(ctx, routes, physIf)
}

func VerifyUpdateCleanup(ctx context.Context) error { return verifyUpdateCleanup(ctx, nil, "") }
