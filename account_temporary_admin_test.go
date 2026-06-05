package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTemporarySuperAdminCanLoginWithoutRoleBinding(t *testing.T) {
	hash, err := hashPassword("Temp1234")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	now := time.Now().UTC()
	p := &AdminAccountPlugin{
		accounts: map[string]accountRecord{
			temporarySuperAdminSeedID: {
				ID:           temporarySuperAdminSeedID,
				Username:     "temp-admin",
				PasswordHash: hash,
				Status:       "enabled",
				IsSuperAdmin: true,
				CreatedAt:    now,
				UpdatedAt:    now,
			},
		},
		roles: map[string][]string{},
	}

	acc, roles, ok, err := p.getAccountByAccount(context.Background(), "temp-admin")
	if err != nil {
		t.Fatalf("getAccountByAccount returned error: %v", err)
	}
	if !ok || acc.ID != temporarySuperAdminSeedID {
		t.Fatalf("account lookup ok=%v account=%+v", ok, acc)
	}
	if len(roles) != 0 {
		t.Fatalf("roles=%v, want empty role slice for temporary super admin", roles)
	}
}

func TestCheckPermissionAllowsSuperAdminWithoutRoleBinding(t *testing.T) {
	const token = "project-admin-token"
	now := time.Now().UTC()
	p := &AdminAccountPlugin{
		accounts: map[string]accountRecord{
			temporarySuperAdminSeedID: {
				ID:           temporarySuperAdminSeedID,
				Username:     "temp-admin",
				Status:       "enabled",
				IsSuperAdmin: true,
				CreatedAt:    now,
				UpdatedAt:    now,
			},
		},
		roles: map[string][]string{},
		lookupProjectAdminSessionAccountID: func(ctx context.Context, gotToken string) (string, error) {
			if gotToken != token {
				t.Fatalf("token=%s, want %s", gotToken, token)
			}
			return temporarySuperAdminSeedID, nil
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/api/account/check-permission", strings.NewReader(`{"session_token":"`+token+`","permission_code":"admin_account.manage"}`))
	rec := httptest.NewRecorder()
	p.handleCheckPermission(rec, req)

	var resp struct {
		Status int `json:"status"`
		Data   struct {
			Allowed        bool     `json:"allowed"`
			IsSuperAdmin   bool     `json:"is_super_admin"`
			MatchedRoleIDs []string `json:"matched_role_ids"`
		} `json:"data"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Status != 0 || !resp.Data.Allowed || !resp.Data.IsSuperAdmin || len(resp.Data.MatchedRoleIDs) != 0 {
		t.Fatalf("status=%d data=%+v body=%s", resp.Status, resp.Data, rec.Body.String())
	}
}
