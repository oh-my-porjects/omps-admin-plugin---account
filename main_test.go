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

	"github.com/DATA-DOG/go-sqlmock"
)

func TestCreateTemporaryAdminRepairsSeedFlags(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	t.Setenv("ADMIN_API_KEY", "test-internal-token")
	mock.ExpectExec(`(?s)INSERT INTO account_accounts .*is_super_admin.*is_temporary.*ON CONFLICT.*is_super_admin = TRUE.*is_temporary = TRUE`).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), temporarySuperAdminSeedID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	p := &AdminAccountPlugin{db: db}
	req := httptest.NewRequest(http.MethodPost, "/api/account/_create-temporary-admin", nil)
	req.Header.Set("X-Internal-Token", "test-internal-token")
	rec := httptest.NewRecorder()

	p.handleCreateTemporaryAdmin(rec, req)

	var resp struct {
		Status int `json:"status"`
		Data   struct {
			Account   string `json:"account"`
			Password  string `json:"password"`
			ExpiresAt string `json:"expires_at"`
		} `json:"data"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Status != 0 {
		t.Fatalf("status=%d body=%s", resp.Status, rec.Body.String())
	}
	if resp.Data.Account == "" || resp.Data.Password == "" || resp.Data.ExpiresAt == "" {
		t.Fatalf("temporary admin response incomplete: %+v", resp.Data)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("sql expectations: %v", err)
	}
}

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

func TestRuntimeURLFallsBackFromAdminProxyHost(t *testing.T) {
	p := &AdminAccountPlugin{}
	req := httptest.NewRequest(http.MethodGet, "/api/account/list", nil)
	req.Host = "omps-shan-admin.link-api.com"
	got := p.runtimeURL(req, "/api/role/detail")
	want := "http://127.0.0.1:8080/api/role/detail"
	if got != want {
		t.Fatalf("runtimeURL = %s, want %s", got, want)
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
	const roleID = "fS9Cmj6bzKBa"
	p, reqTemplate, closeServer := newRoleBackedPlugin(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/role/detail" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		writeTestJSON(t, w, 0, map[string]any{"role_id": roleID, "status": "enabled"})
	})
	defer closeServer()
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
	p.roles = map[string][]string{shortAccountID: {roleID}}

	req := httptest.NewRequest(http.MethodPost, "/api/account/_validate-password", strings.NewReader(`{"account":"project-admin","password":"Admin@123"}`))
	req.Host = reqTemplate.Host
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

func TestHandleMeAcceptsProjectAdminSessionToken(t *testing.T) {
	const token = "project-admin-token"
	const accountID = "pD1BjYBEQbEc"
	now := time.Now().UTC()
	p := &AdminAccountPlugin{
		accounts: map[string]accountRecord{
			accountID: {
				ID:           accountID,
				Username:     "project-admin",
				Status:       "enabled",
				IsSuperAdmin: true,
				CreatedAt:    now,
				UpdatedAt:    now,
			},
		},
		roles: map[string][]string{accountID: {rootRoleID}},
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
		Data   struct {
			AccountID    string `json:"account_id"`
			IsSuperAdmin bool   `json:"is_super_admin"`
			Roles        []struct {
				RoleID string `json:"role_id"`
			} `json:"roles"`
		} `json:"data"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Status != 0 {
		t.Fatalf("status=%d body=%s", resp.Status, rec.Body.String())
	}
	if resp.Data.AccountID != accountID || !resp.Data.IsSuperAdmin || len(resp.Data.Roles) != 0 {
		t.Fatalf("data=%+v, want project admin super account without role list", resp.Data)
	}
}

func TestAccountManageAndPermissionAcceptProjectAdminSessionToken(t *testing.T) {
	const token = "project-admin-token"
	const accountID = "pD1BjYBEQbEc"
	now := time.Now().UTC()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/role/detail":
			writeTestJSON(t, w, 0, map[string]any{
				"role_id": rootRoleID,
				"status":  "enabled",
				"permissions": []map[string]string{
					{"code": "system.manage"},
				},
			})
		case "/api/role/check-permission":
			writeTestJSON(t, w, 0, map[string]any{"allowed": true, "role_status": "enabled"})
		default:
			t.Fatalf("unexpected role API path: %s", r.URL.Path)
		}
	}))
	defer server.Close()
	p := &AdminAccountPlugin{
		runtimeAddr: server.URL,
		accounts: map[string]accountRecord{
			accountID: {
				ID:           accountID,
				Username:     "project-admin",
				Status:       "enabled",
				IsSuperAdmin: true,
				CreatedAt:    now,
				UpdatedAt:    now,
			},
		},
		roles: map[string][]string{accountID: {rootRoleID}},
		lookupProjectAdminSessionAccountID: func(ctx context.Context, gotToken string) (string, error) {
			if gotToken != token {
				t.Fatalf("token=%s, want %s", gotToken, token)
			}
			return accountID, nil
		},
	}

	detailReq := httptest.NewRequest(http.MethodGet, "/api/account/detail?operator_session_token="+token+"&account_id="+accountID, nil)
	detailRec := httptest.NewRecorder()
	p.handleAccountDetail(detailRec, detailReq)
	var detailResp struct {
		Status int `json:"status"`
		Data   struct {
			AccountID string `json:"account_id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(detailRec.Body).Decode(&detailResp); err != nil {
		t.Fatalf("decode detail response: %v", err)
	}
	if detailResp.Status != 0 || detailResp.Data.AccountID != accountID {
		t.Fatalf("detail response status=%d data=%+v body=%s", detailResp.Status, detailResp.Data, detailRec.Body.String())
	}

	checkReq := httptest.NewRequest(http.MethodPost, "/api/account/check-permission", strings.NewReader(`{"session_token":"`+token+`","permission_code":"system.manage"}`))
	checkRec := httptest.NewRecorder()
	p.handleCheckPermission(checkRec, checkReq)
	var checkResp struct {
		Status int `json:"status"`
		Data   struct {
			Allowed      bool `json:"allowed"`
			IsSuperAdmin bool `json:"is_super_admin"`
		} `json:"data"`
	}
	if err := json.NewDecoder(checkRec.Body).Decode(&checkResp); err != nil {
		t.Fatalf("decode check response: %v", err)
	}
	if checkResp.Status != 0 || !checkResp.Data.Allowed || !checkResp.Data.IsSuperAdmin {
		t.Fatalf("check response status=%d data=%+v body=%s", checkResp.Status, checkResp.Data, checkRec.Body.String())
	}
}

func TestHandleAccountDeleteSuccessRemovesAccountAndRoles(t *testing.T) {
	now := time.Now().UTC()
	p := &AdminAccountPlugin{
		accounts: map[string]accountRecord{
			rootAccountID: {
				ID:           rootAccountID,
				Username:     "root",
				Status:       "enabled",
				IsSuperAdmin: true,
				CreatedAt:    now,
				UpdatedAt:    now,
			},
			operatorAccountID: {
				ID:        operatorAccountID,
				Username:  "operator",
				Status:    "enabled",
				CreatedAt: now,
				UpdatedAt: now,
			},
		},
		roles: map[string][]string{
			rootAccountID:     {rootRoleID},
			operatorAccountID: {supportRoleID},
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/api/admin/account/delete", strings.NewReader(`{"operator_session_token":"","account_id":"`+operatorAccountID+`"}`))
	req.Header.Set("X-Account-ID", rootAccountID)
	rec := httptest.NewRecorder()
	p.handleAccountDelete(rec, req)

	var resp struct {
		Status int `json:"status"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Status != 0 {
		t.Fatalf("status=%d body=%s", resp.Status, rec.Body.String())
	}
	if _, ok := p.accounts[operatorAccountID]; ok {
		t.Fatalf("target account still exists")
	}
	if roles, ok := p.roles[operatorAccountID]; ok || len(roles) > 0 {
		t.Fatalf("target roles still exist: %v", roles)
	}
}

func TestHandleAccountDeleteRejectsSelf(t *testing.T) {
	now := time.Now().UTC()
	p := &AdminAccountPlugin{
		accounts: map[string]accountRecord{
			rootAccountID: {
				ID:           rootAccountID,
				Username:     "root",
				Status:       "enabled",
				IsSuperAdmin: true,
				CreatedAt:    now,
				UpdatedAt:    now,
			},
		},
		roles: map[string][]string{rootAccountID: {rootRoleID}},
	}

	req := httptest.NewRequest(http.MethodPost, "/api/admin/account/delete", strings.NewReader(`{"operator_session_token":"","account_id":"`+rootAccountID+`"}`))
	req.Header.Set("X-Account-ID", rootAccountID)
	rec := httptest.NewRecorder()
	p.handleAccountDelete(rec, req)

	var resp struct {
		Status int `json:"status"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Status != 2295 {
		t.Fatalf("status=%d body=%s", resp.Status, rec.Body.String())
	}
}

func TestHandleAccountDeleteRejectsNormalOperatorDeletingSuperAdmin(t *testing.T) {
	now := time.Now().UTC()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/role/detail":
			writeTestJSON(t, w, 0, map[string]any{"role_id": supportRoleID, "status": "enabled"})
		case "/api/role/check-permission":
			writeTestJSON(t, w, 0, map[string]any{"allowed": true, "role_status": "enabled"})
		default:
			t.Fatalf("unexpected role API path: %s", r.URL.Path)
		}
	}))
	defer server.Close()
	p := &AdminAccountPlugin{
		runtimeAddr: server.URL,
		accounts: map[string]accountRecord{
			rootAccountID: {
				ID:           rootAccountID,
				Username:     "root",
				Status:       "enabled",
				IsSuperAdmin: true,
				CreatedAt:    now,
				UpdatedAt:    now,
			},
			operatorAccountID: {
				ID:        operatorAccountID,
				Username:  "operator",
				Status:    "enabled",
				CreatedAt: now,
				UpdatedAt: now,
			},
		},
		roles: map[string][]string{
			rootAccountID:     {rootRoleID},
			operatorAccountID: {supportRoleID},
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/api/admin/account/delete", strings.NewReader(`{"operator_session_token":"","account_id":"`+rootAccountID+`"}`))
	req.Header.Set("X-Account-ID", operatorAccountID)
	rec := httptest.NewRecorder()
	p.handleAccountDelete(rec, req)

	var resp struct {
		Status int `json:"status"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Status != 2296 {
		t.Fatalf("status=%d body=%s", resp.Status, rec.Body.String())
	}
}

func TestHandleAccountDeleteMissingAccount(t *testing.T) {
	now := time.Now().UTC()
	p := &AdminAccountPlugin{
		accounts: map[string]accountRecord{
			rootAccountID: {
				ID:           rootAccountID,
				Username:     "root",
				Status:       "enabled",
				IsSuperAdmin: true,
				CreatedAt:    now,
				UpdatedAt:    now,
			},
		},
		roles: map[string][]string{rootAccountID: {rootRoleID}},
	}

	req := httptest.NewRequest(http.MethodPost, "/api/admin/account/delete", strings.NewReader(`{"operator_session_token":"","account_id":"10000000-0000-0000-0000-000000009999"}`))
	req.Header.Set("X-Account-ID", rootAccountID)
	rec := httptest.NewRecorder()
	p.handleAccountDelete(rec, req)

	var resp struct {
		Status int `json:"status"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Status != 2294 {
		t.Fatalf("status=%d body=%s", resp.Status, rec.Body.String())
	}
}
