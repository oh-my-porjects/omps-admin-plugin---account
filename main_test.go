package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
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
	rec := httptest.NewRecorder()

	acc, ok := p.requireAccountManageToken(rec, req, "", 2231, 2232, 2235)
	if !ok {
		t.Fatalf("requireAccountManageToken rejected project admin header: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if acc.ID != rootAccountID {
		t.Fatalf("account id=%s, want %s", acc.ID, rootAccountID)
	}
}

func TestRequireAccountManageTokenAcceptsProjectAdminShortID(t *testing.T) {
	const shortAccountID = "pD1BjYBEQbEc"
	p := &AdminAccountPlugin{}
	now := time.Now().UTC()
	p.accounts = map[string]accountRecord{
		shortAccountID: {
			ID:           shortAccountID,
			Username:     "project-admin",
			Status:       "enabled",
			IsSuperAdmin: true,
			CreatedAt:    now,
			UpdatedAt:    now,
		},
	}
	p.roles = map[string][]string{shortAccountID: {"fS9Cmj6bzKBa"}}

	req := httptest.NewRequest(http.MethodGet, "/api/account/list", nil)
	req.Header.Set("X-Account-ID", shortAccountID)
	rec := httptest.NewRecorder()

	acc, ok := p.requireAccountManageToken(rec, req, "", 2231, 2232, 2235)
	if !ok {
		t.Fatalf("requireAccountManageToken rejected short project admin id: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if acc.ID != shortAccountID {
		t.Fatalf("account id=%s, want %s", acc.ID, shortAccountID)
	}
}

func TestValidatePasswordRouteSupportsRuntimeAdminLogin(t *testing.T) {
	p := &AdminAccountPlugin{}
	hash, err := hashPassword("Admin@123")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	const shortAccountID = "pD1BjYBEQbEc"
	p.accounts = map[string]accountRecord{
		shortAccountID: {
			ID:           shortAccountID,
			Username:     "project-admin",
			PasswordHash: hash,
			Status:       "enabled",
			IsSuperAdmin: true,
			CreatedAt:    time.Now().UTC(),
			UpdatedAt:    time.Now().UTC(),
		},
	}
	p.roles = map[string][]string{shortAccountID: {"fS9Cmj6bzKBa"}}

	req := httptest.NewRequest(http.MethodPost, "/api/account/_validate-password", strings.NewReader(`{"account":"project-admin","password":"Admin@123"}`))
	rec := httptest.NewRecorder()
	p.handleValidatePassword(rec, req)

	var resp struct {
		Status int `json:"status"`
		Data   struct {
			AccountID    string   `json:"account_id"`
			IsSuperAdmin bool     `json:"is_super_admin"`
			RoleIDs      []string `json:"role_ids"`
		} `json:"data"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Status != 0 {
		t.Fatalf("status=%d body=%s", resp.Status, rec.Body.String())
	}
	if resp.Data.AccountID != shortAccountID || !resp.Data.IsSuperAdmin {
		t.Fatalf("data=%+v, want account_id=%s super admin", resp.Data, shortAccountID)
	}
}
