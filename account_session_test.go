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
