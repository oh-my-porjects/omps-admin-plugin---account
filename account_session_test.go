package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHandleMeRejectsSessionAccountWithoutValidRole(t *testing.T) {
	const token = "project-admin-token"
	const accountID = "pD1BjYBEQbEc"
	now := time.Now().UTC()
	p := &AdminAccountPlugin{
		accounts: map[string]accountRecord{
			accountID: {
				ID:        accountID,
				Username:  "project-admin",
				Status:    "enabled",
				CreatedAt: now,
				UpdatedAt: now,
			},
		},
		roles: map[string][]string{accountID: {}},
		lookupProjectAdminSessionAccountID: func(ctx context.Context, gotToken string) (string, error) {
			if gotToken != token {
				t.Fatalf("token=%s, want %s", gotToken, token)
			}
			return accountID, nil
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/account/me?session_token="+token, nil)
	rec := httptest.NewRecorder()
	p.handleMe(rec, req)

	var resp struct {
		Status int `json:"status"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Status != 2214 {
		t.Fatalf("status=%d body=%s, want 2214", resp.Status, rec.Body.String())
	}
}

func TestHandleMeMapsSingleInvalidRoleToAccountDisabled(t *testing.T) {
	const token = "project-admin-token"
	const accountID = "pD1BjYBEQbEc"
	const roleID = "rD1BjYBEQbEc"
	now := time.Now().UTC()
	p, reqTemplate, closeServer := newRoleBackedPlugin(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/role/detail" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if gotRoleID := r.URL.Query().Get("role_id"); gotRoleID != roleID {
			t.Fatalf("role_id=%s, want %s", gotRoleID, roleID)
		}
		writeTestJSON(t, w, 0, map[string]any{"role_id": roleID, "status": "disabled"})
	})
	defer closeServer()
	p.accounts[accountID] = accountRecord{
		ID:        accountID,
		Username:  "project-admin",
		Status:    "enabled",
		CreatedAt: now,
		UpdatedAt: now,
	}
	p.roles[accountID] = []string{roleID}
	p.lookupProjectAdminSessionAccountID = func(ctx context.Context, gotToken string) (string, error) {
		if gotToken != token {
			t.Fatalf("token=%s, want %s", gotToken, token)
		}
		return accountID, nil
	}

	req := httptest.NewRequest(http.MethodGet, "/api/account/me?session_token="+token, nil)
	req.Host = reqTemplate.Host
	rec := httptest.NewRecorder()
	p.handleMe(rec, req)

	var resp struct {
		Status int `json:"status"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Status != 2214 {
		t.Fatalf("status=%d body=%s, want 2214", resp.Status, rec.Body.String())
	}
}
