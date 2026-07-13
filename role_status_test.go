package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	testAccountID        = "20000000-0000-0000-0000-000000000001"
	testRoleID           = "20000000-0000-0000-0000-000000000101"
	testSecondRoleID     = "20000000-0000-0000-0000-000000000102"
	testThirdRoleID      = "20000000-0000-0000-0000-000000000103"
	testPermissionRoleID = "20000000-0000-0000-0000-000000000104"
)

func TestRolesAvailableRejectsDeletedDisabledAndMissing(t *testing.T) {
	cases := []struct {
		name   string
		status string
		body   map[string]any
		want   bool
	}{
		{name: "enabled", body: map[string]any{"role_id": testRoleID, "status": "enabled"}, want: true},
		{name: "disabled", body: map[string]any{"role_id": testRoleID, "status": "disabled"}, want: false},
		{name: "deleted_status", body: map[string]any{"role_id": testRoleID, "status": "deleted"}, want: false},
		{name: "deleted_at", body: map[string]any{"role_id": testRoleID, "status": "enabled", "deleted_at": "2026-05-21T02:00:00Z"}, want: false},
		{name: "missing", status: "missing", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, req, closeServer := newRoleBackedPlugin(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/role/detail" {
					t.Fatalf("unexpected path: %s", r.URL.Path)
				}
				if tc.status == "missing" {
					writeTestJSON(t, w, 2122, nil)
					return
				}
				writeTestJSON(t, w, 0, tc.body)
			})
			defer closeServer()

			got, err := p.rolesAvailable(req, []string{testRoleID})
			if err != nil {
				t.Fatalf("rolesAvailable returned error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("rolesAvailable = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNormalizeRoleStatusTreatsDeletedStatusAsDeleted(t *testing.T) {
	got := normalizeRoleStatus(adminRoleDetail{Status: "deleted"})
	if got != "deleted" {
		t.Fatalf("normalizeRoleStatus = %q, want deleted", got)
	}
}

func TestCleanAndValidateRolesRequiresExactlyOneRole(t *testing.T) {
	p, req, closeServer := newRoleBackedPlugin(t, func(w http.ResponseWriter, r *http.Request) {
		writeTestJSON(t, w, 0, map[string]any{"role_id": testRoleID, "status": "enabled"})
	})
	defer closeServer()

	cases := []struct {
		name  string
		roles []string
		want  int
	}{
		{name: "empty", roles: []string{}, want: 2225},
		{name: "multiple", roles: []string{testRoleID, testSecondRoleID}, want: 2225},
		{name: "duplicate", roles: []string{testRoleID, testRoleID}, want: 2225},
		{name: "single", roles: []string{" " + testRoleID + " "}, want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			roles, ok := p.cleanAndValidateRoles(rec, req, tc.roles, 2225, 2226)
			if tc.want == 0 {
				if !ok || len(roles) != 1 || roles[0] != testRoleID {
					t.Fatalf("roles = %v ok = %v, want single role", roles, ok)
				}
				return
			}
			if ok {
				t.Fatalf("ok = true, want false")
			}
			var resp struct {
				Status int `json:"status"`
			}
			if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if resp.Status != tc.want {
				t.Fatalf("status = %d, want %d", resp.Status, tc.want)
			}
		})
	}
}

func TestNormalizeAccountRolesKeepsFirstEnabledRole(t *testing.T) {
	p, req, closeServer := newRoleBackedPlugin(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/role/detail" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		roleID := r.URL.Query().Get("role_id")
		switch roleID {
		case testRoleID:
			writeTestJSON(t, w, 0, map[string]any{"role_id": roleID, "status": "disabled"})
		case testSecondRoleID:
			writeTestJSON(t, w, 0, map[string]any{"role_id": roleID, "status": "enabled"})
		default:
			t.Fatalf("unexpected role_id: %s", roleID)
		}
	})
	defer closeServer()
	_ = req
	p.seedAccount(t, "operator", "Operator@123", "enabled", false, []string{testRoleID, testSecondRoleID})

	_, roles, ok, err := p.getAccountByID(req.Context(), testAccountID)
	if err != nil {
		t.Fatalf("getAccountByID returned error: %v", err)
	}
	if !ok {
		t.Fatalf("account missing")
	}
	if len(roles) != 1 || roles[0] != testSecondRoleID {
		t.Fatalf("roles = %v, want [%s]", roles, testSecondRoleID)
	}
	if stored := p.roles[testAccountID]; len(stored) != 1 || stored[0] != testSecondRoleID {
		t.Fatalf("stored roles = %v, want [%s]", stored, testSecondRoleID)
	}
}

func TestHandleLoginRejectsInvalidBoundRole(t *testing.T) {
	p, reqTemplate, closeServer := newRoleBackedPlugin(t, func(w http.ResponseWriter, r *http.Request) {
		writeTestJSON(t, w, 0, map[string]any{"role_id": testRoleID, "status": "deleted"})
	})
	defer closeServer()
	p.seedAccount(t, "operator", "Operator@123", "enabled", false, []string{testRoleID})

	body := strings.NewReader(`{"account":"operator","password":"Operator@123"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/account/login", body)
	req.Host = reqTemplate.Host
	rec := httptest.NewRecorder()
	p.handleLogin(rec, req)

	var resp struct {
		Status int `json:"status"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Status != 2203 {
		t.Fatalf("status = %d, want 2203", resp.Status)
	}
}

func TestEvaluateRolePermissionReturnsAllRoleStatesAndDeniesInvalidRole(t *testing.T) {
	p, req, closeServer := newRoleBackedPlugin(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/role/detail":
			roleID := r.URL.Query().Get("role_id")
			switch roleID {
			case testRoleID:
				writeTestJSON(t, w, 0, map[string]any{"role_id": roleID, "status": "disabled"})
			case testSecondRoleID:
				writeTestJSON(t, w, 0, map[string]any{"role_id": roleID, "status": "enabled", "deleted_at": "2026-05-21T02:00:00Z"})
			case testThirdRoleID:
				writeTestJSON(t, w, 2122, nil)
			case testPermissionRoleID:
				writeTestJSON(t, w, 0, map[string]any{"role_id": roleID, "status": "enabled"})
			default:
				t.Fatalf("unexpected role_id: %s", roleID)
			}
		case "/api/role/check-permission":
			writeTestJSON(t, w, 0, map[string]any{"allowed": true, "role_status": "disabled"})
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	})
	defer closeServer()

	roleIDs := []string{testRoleID, testSecondRoleID, testThirdRoleID, testPermissionRoleID}
	matched, roles, err := p.evaluateRolePermission(req, roleIDs, "admin_account.manage")
	if err != nil {
		t.Fatalf("evaluateRolePermission returned error: %v", err)
	}
	if len(matched) != 0 {
		t.Fatalf("matched = %v, want empty", matched)
	}
	if len(roles) != len(roleIDs) {
		t.Fatalf("roles length = %d, want %d: %+v", len(roles), len(roleIDs), roles)
	}
	wantStatuses := []string{"disabled", "deleted", "missing", "disabled"}
	for i, want := range wantStatuses {
		if roles[i].RoleID != roleIDs[i] || roles[i].RoleStatus != want {
			t.Fatalf("roles[%d] = %+v, want role_id=%s status=%s", i, roles[i], roleIDs[i], want)
		}
	}
}

func newRoleBackedPlugin(t *testing.T, handler http.HandlerFunc) (*AdminAccountPlugin, *http.Request, func()) {
	t.Helper()
	p := &AdminAccountPlugin{
		logger:          slog.Default(),
		sessionTTL:      time.Hour,
		internalRequest: newRoleInternalRequest(t, handler),
		accounts:        map[string]accountRecord{},
		roles:           map[string][]string{},
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	return p, req, func() {}
}

func newRoleInternalRequest(t *testing.T, handler http.HandlerFunc) func(context.Context, string, string, []byte, http.Header) (int, http.Header, []byte, error) {
	t.Helper()
	return func(ctx context.Context, method, target string, body []byte, headers http.Header) (int, http.Header, []byte, error) {
		req := httptest.NewRequest(method, target, bytes.NewReader(body)).WithContext(ctx)
		req.Header = headers.Clone()
		rec := httptest.NewRecorder()
		handler(rec, req)
		return rec.Code, rec.Header().Clone(), rec.Body.Bytes(), nil
	}
}

func (p *AdminAccountPlugin) seedAccount(t *testing.T, account, password, status string, superAdmin bool, roleIDs []string) {
	t.Helper()
	hash, err := hashPassword(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	p.accounts[testAccountID] = accountRecord{
		ID:           testAccountID,
		Username:     account,
		PasswordHash: hash,
		Status:       status,
		IsSuperAdmin: superAdmin,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}
	p.roles[testAccountID] = append([]string(nil), roleIDs...)
}

func writeTestJSON(t *testing.T, w http.ResponseWriter, status int, data any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{"status": status, "data": data, "msg": ""}); err != nil {
		t.Fatalf("write json: %v", err)
	}
}
