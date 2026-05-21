package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPluginName(t *testing.T) {
	name := Plugin.Name()
	if name == "" {
		t.Fatal("Name() 不应为空")
	}
}

func TestPluginInit(t *testing.T) {
	ctx := PluginContext{
		Logger: slog.Default(),
	}
	if err := Plugin.Init(ctx); err != nil {
		t.Errorf("Init 失败: %v", err)
	}
}

func TestPluginShutdown(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1)
	defer cancel()
	if err := Plugin.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown(ctx) 失败: %v", err)
	}
}

func TestRequireAccountManageTokenFallsBackToProjectAdminHeader(t *testing.T) {
	p := &AdminAccountPlugin{}
	now := time.Now().UTC()
	p.accounts = map[string]accountRecord{
		rootAccountID: {
			ID:           rootAccountID,
			Username:     "root",
			Status:       "enabled",
			IsSuperAdmin: true,
			CreatedAt:    now,
			UpdatedAt:    now,
		},
	}
	p.roles = map[string][]string{rootAccountID: {rootRoleID}}

	req := httptest.NewRequest(http.MethodGet, "/api/account/list", nil)
	req.Header.Set("X-Account-ID", rootAccountID)
	req.Header.Set("X-Admin-Session-Token", "project-session")
	req.Header.Set("X-Admin-Role", "admin")
	rec := httptest.NewRecorder()

	acc, ok := p.requireAccountManageToken(rec, req, "", 2231, 2232, 2235)
	if !ok {
		t.Fatalf("requireAccountManageToken rejected project admin header: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if acc.ID != rootAccountID {
		t.Fatalf("account id=%s, want %s", acc.ID, rootAccountID)
	}
}

func TestRequireAccountManageTokenFallsBackWhenAccountRecordMissing(t *testing.T) {
	p := &AdminAccountPlugin{}
	req := httptest.NewRequest(http.MethodGet, "/api/account/list", nil)
	req.Header.Set("X-Account-ID", "pD1BjYBEQbEc")
	req.Header.Set("X-Admin-Session-Token", "project-session")
	req.Header.Set("X-Admin-Role", "admin")
	rec := httptest.NewRecorder()

	acc, ok := p.requireAccountManageToken(rec, req, "", 2231, 2232, 2235)
	if !ok {
		t.Fatalf("requireAccountManageToken rejected project admin session: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !acc.IsSuperAdmin || acc.Status != "enabled" {
		t.Fatalf("fallback account = %#v", acc)
	}
}

func TestRequireAccountManageTokenRejectsProjectOperatorFallback(t *testing.T) {
	p := &AdminAccountPlugin{}
	req := httptest.NewRequest(http.MethodGet, "/api/account/list", nil)
	req.Header.Set("X-Account-ID", "pD1BjYBEQbEc")
	req.Header.Set("X-Admin-Session-Token", "project-session")
	req.Header.Set("X-Admin-Role", "operator")
	rec := httptest.NewRecorder()

	if _, ok := p.requireAccountManageToken(rec, req, "", 2231, 2232, 2235); ok {
		t.Fatal("operator project session should not manage accounts")
	}
}
