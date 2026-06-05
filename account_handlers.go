package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var (
	uuidRE           = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	recordIDRE       = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)
	permissionCodeRE = regexp.MustCompile(`^[a-z0-9._-]{3,80}$`)
)

func (p *AdminAccountPlugin) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Account  string `json:"account"`
		Password string `json:"password"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	req.Account = strings.TrimSpace(req.Account)
	if !validAccount(req.Account) || !validPassword(req.Password) {
		writeJSON(w, 2201, nil, "账号和密码参数非法")
		return
	}

	acc, roles, ok, err := p.getAccountByAccount(r.Context(), req.Account)
	if err != nil {
		if errors.Is(err, errNoValidAccountRole) {
			writeJSON(w, 2203, nil, "账号绑定角色已失效")
			return
		}
		writeJSON(w, 2204, nil, "登录失败")
		return
	}
	if !ok || !verifyPassword(acc.PasswordHash, req.Password) {
		writeJSON(w, 2202, nil, "账号或密码错误")
		return
	}
	if acc.Status != "enabled" {
		writeJSON(w, 2203, nil, "账号已停用")
		return
	}
	if available, err := p.rolesAvailable(r, roles); err != nil {
		writeJSON(w, 2204, nil, "登录失败")
		return
	} else if !available {
		writeJSON(w, 2203, nil, "账号绑定角色已失效")
		return
	}
	token, expiresAt, err := p.createSession(r.Context(), acc.ID)
	if err != nil {
		writeJSON(w, 2204, nil, "登录失败")
		return
	}
	writeJSON(w, 0, map[string]any{
		"account":       accountToResponse(acc, roles),
		"session_token": token,
		"expires_at":    expiresAt.Format(time.RFC3339),
		"ttl_seconds":   int(p.sessionTTL.Seconds()),
	}, "ok")
}

func (p *AdminAccountPlugin) handleMe(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.URL.Query().Get("session_token"))
	if token == "" {
		writeJSON(w, 2211, nil, "会话令牌参数非法")
		return
	}
	acc, roles, state := p.currentAccountByAnySessionToken(r, token)
	if state == sessionMissing {
		writeJSON(w, 2212, nil, "会话不存在或已过期")
		return
	}
	if state == sessionAccountMissing {
		writeJSON(w, 2213, nil, "账号不存在")
		return
	}
	if state == sessionAccountInvalidRole {
		writeJSON(w, 2214, nil, "账号已禁用")
		return
	}
	if acc.Status != "enabled" {
		writeJSON(w, 2214, nil, "账号已禁用")
		return
	}
	resp, err := p.accountPermissionResponse(r, acc, roles)
	if err != nil {
		writeJSON(w, 2215, nil, "查询当前账号失败")
		return
	}
	writeJSON(w, 0, resp, "ok")
}

func (p *AdminAccountPlugin) handleValidatePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Account  string `json:"account"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 2281, nil, "请求体解析失败")
		return
	}
	req.Account = strings.TrimSpace(req.Account)
	if !validAccount(req.Account) || !validPassword(req.Password) {
		writeJSON(w, 2281, nil, "账号和密码参数非法")
		return
	}
	acc, roles, ok, err := p.getAccountByAccount(r.Context(), req.Account)
	if err != nil {
		if errors.Is(err, errNoValidAccountRole) {
			writeJSON(w, 2284, nil, "账号校验失败")
			return
		}
		writeJSON(w, 2284, nil, "账号校验失败")
		return
	}
	if !ok || !verifyPassword(acc.PasswordHash, req.Password) {
		writeJSON(w, 2282, nil, "账号或密码错误")
		return
	}
	if acc.Status != "enabled" {
		writeJSON(w, 2283, nil, "账号已停用")
		return
	}
	if available, err := p.rolesAvailable(r, roles); err != nil || !available {
		writeJSON(w, 2284, nil, "账号校验失败")
		return
	}
	writeJSON(w, 0, map[string]any{
		"account_id":     acc.ID,
		"account":        acc.Username,
		"is_super_admin": acc.IsSuperAdmin,
		"role_ids":       roles,
	}, "ok")
}

func (p *AdminAccountPlugin) handleAccountCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OperatorSessionToken string   `json:"operator_session_token"`
		Account              string   `json:"account"`
		Password             string   `json:"password"`
		Status               string   `json:"status"`
		RoleIDs              []string `json:"role_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 2221, nil, "请求体解析失败")
		return
	}
	if _, ok := p.requireAccountManageToken(w, r, req.OperatorSessionToken, 2221, 2222, 2227); !ok {
		return
	}
	req.Account = strings.TrimSpace(req.Account)
	status := normalizeStatus(req.Status)
	roleIDs, ok := p.cleanAndValidateRoles(w, r, req.RoleIDs, 2225, 2226)
	if !ok {
		return
	}
	if !validAccount(req.Account) || !validPassword(req.Password) || status == "" {
		writeJSON(w, 2223, nil, "账号参数非法")
		return
	}
	if _, _, exists, err := p.getAccountByAccount(r.Context(), req.Account); err != nil {
		writeJSON(w, 2227, nil, "创建账号失败")
		return
	} else if exists {
		writeJSON(w, 2224, nil, "账号已存在")
		return
	}
	acc, roles, err := p.createAccount(r.Context(), req.Account, req.Password, status, roleIDs)
	if err != nil {
		writeJSON(w, 2227, nil, "创建账号失败")
		return
	}
	writeJSON(w, 0, accountToResponse(acc, roles), "ok")
}

func (p *AdminAccountPlugin) handleAccountList(w http.ResponseWriter, r *http.Request) {
	if _, ok := p.requireAccountManageToken(w, r, r.URL.Query().Get("operator_session_token"), 2231, 2232, 2235); !ok {
		return
	}
	page, pageSize, ok := parsePage(r)
	if !ok {
		writeJSON(w, 2233, nil, "分页参数非法")
		return
	}
	status := r.URL.Query().Get("status")
	keyword := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("keyword")))
	if !validListFilters(status, keyword) {
		writeJSON(w, 2234, nil, "状态或关键词参数非法")
		return
	}
	items, total, err := p.listAccounts(r.Context(), status, keyword, page, pageSize)
	if err != nil {
		writeJSON(w, 2235, nil, "查询账号列表失败")
		return
	}
	writeJSON(w, 0, map[string]any{"items": items, "total": total, "page": page, "page_size": pageSize}, "ok")
}

func (p *AdminAccountPlugin) handleAccountDetail(w http.ResponseWriter, r *http.Request) {
	if _, ok := p.requireAccountManageToken(w, r, r.URL.Query().Get("operator_session_token"), 2241, 2242, 2245); !ok {
		return
	}
	accountID := strings.TrimSpace(r.URL.Query().Get("account_id"))
	if !validRecordID(accountID) {
		writeJSON(w, 2243, nil, "account_id 参数非法")
		return
	}
	acc, roles, ok, err := p.getAccountByID(r.Context(), accountID)
	if err != nil {
		writeJSON(w, 2245, nil, "查询账号详情失败")
		return
	}
	if !ok {
		writeJSON(w, 2244, nil, "账号不存在")
		return
	}
	resp, err := p.accountDetailResponse(r, acc, roles)
	if err != nil {
		writeJSON(w, 2245, nil, "查询账号详情失败")
		return
	}
	writeJSON(w, 0, resp, "ok")
}

func (p *AdminAccountPlugin) handleAccountUpdate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OperatorSessionToken string   `json:"operator_session_token"`
		AccountID            string   `json:"account_id"`
		Status               string   `json:"status"`
		RoleIDs              []string `json:"role_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 2251, nil, "请求体解析失败")
		return
	}
	operator, ok := p.requireAccountManageToken(w, r, req.OperatorSessionToken, 2251, 2252, 2258)
	if !ok {
		return
	}
	status := normalizeStatus(req.Status)
	roleIDs, ok := p.cleanAndValidateRoles(w, r, req.RoleIDs, 2255, 2256)
	if !ok {
		return
	}
	if !validRecordID(req.AccountID) {
		writeJSON(w, 2253, nil, "account_id 参数非法")
		return
	}
	if status == "" {
		writeJSON(w, 2255, nil, "状态参数非法")
		return
	}
	target, _, exists, err := p.getAccountByID(r.Context(), req.AccountID)
	if err != nil {
		writeJSON(w, 2258, nil, "更新账号失败")
		return
	}
	if !exists {
		writeJSON(w, 2254, nil, "账号不存在")
		return
	}
	if target.IsSuperAdmin && !operator.IsSuperAdmin {
		writeJSON(w, 2257, nil, "普通后台账号不能修改超级管理员账号")
		return
	}
	acc, roles, exists, err := p.updateAccount(r.Context(), req.AccountID, status, roleIDs)
	if err != nil {
		writeJSON(w, 2258, nil, "更新账号失败")
		return
	}
	if !exists {
		writeJSON(w, 2254, nil, "账号不存在")
		return
	}
	writeJSON(w, 0, accountToResponse(acc, roles), "ok")
}

func (p *AdminAccountPlugin) handleCheckPermission(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionToken   string `json:"session_token"`
		PermissionCode string `json:"permission_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 2271, nil, "请求体解析失败")
		return
	}
	req.SessionToken = strings.TrimSpace(req.SessionToken)
	req.PermissionCode = strings.TrimSpace(req.PermissionCode)
	if req.SessionToken == "" {
		writeJSON(w, 2271, nil, "会话令牌参数非法")
		return
	}
	if !validPermissionCode(req.PermissionCode) {
		writeJSON(w, 2273, nil, "权限参数非法")
		return
	}
	acc, roles, state := p.currentAccountByAnySessionToken(r, req.SessionToken)
	if state == sessionMissing {
		writeJSON(w, 2272, nil, "会话不存在或已过期")
		return
	}
	if state == sessionAccountMissing || state == sessionAccountInvalidRole || acc.Status != "enabled" {
		writeJSON(w, 2274, nil, "账号不存在或已禁用")
		return
	}
	if len(roles) != 1 {
		writeJSON(w, 2274, nil, "账号不存在、已禁用或没有有效角色")
		return
	}
	if acc.IsSuperAdmin {
		writeJSON(w, 0, map[string]any{
			"allowed":          true,
			"is_super_admin":   true,
			"matched_role_ids": []string{},
		}, "ok")
		return
	}
	matched, roleStates, err := p.evaluateRolePermission(r, roles, req.PermissionCode)
	if err != nil {
		writeJSON(w, 2275, nil, "权限校验失败")
		return
	}
	if len(roleStates) != 1 || roleStates[0].RoleStatus != "enabled" {
		writeJSON(w, 2274, nil, "账号不存在、已禁用或没有有效角色")
		return
	}
	writeJSON(w, 0, map[string]any{
		"allowed":          len(matched) > 0,
		"is_super_admin":   false,
		"matched_role_ids": matched,
		"roles":            roleStates,
	}, "ok")
}

func (p *AdminAccountPlugin) currentAccountByToken(r *http.Request, token string) (accountRecord, []string, sessionAccountState) {
	token = strings.TrimSpace(token)
	if token == "" {
		return accountRecord{}, nil, sessionMissing
	}
	acc, roles, state, err := p.getAccountBySessionState(r.Context(), token)
	if err != nil {
		return accountRecord{}, nil, sessionMissing
	}
	return acc, roles, state
}

func (p *AdminAccountPlugin) currentAccountByAnySessionToken(r *http.Request, token string) (accountRecord, []string, sessionAccountState) {
	acc, roles, state := p.currentAccountByToken(r, token)
	if state != sessionMissing {
		return acc, roles, state
	}
	return p.currentProjectAdminAccountByToken(r, token)
}

func (p *AdminAccountPlugin) currentProjectAdminAccount(r *http.Request) (accountRecord, []string, sessionAccountState) {
	if accountID := strings.TrimSpace(r.Header.Get("X-Account-ID")); accountID != "" {
		acc, roles, ok, err := p.getAccountByID(r.Context(), accountID)
		if err != nil {
			return accountRecord{}, nil, sessionMissing
		}
		if !ok {
			return accountRecord{}, nil, sessionAccountMissing
		}
		return acc, roles, sessionAccountOK
	}

	token := strings.TrimSpace(r.Header.Get("X-Admin-Session-Token"))
	if token == "" {
		token = strings.TrimSpace(r.Header.Get("X-Admin-Token"))
	}
	if token == "" {
		token = strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	}
	if token == "" {
		return accountRecord{}, nil, sessionMissing
	}
	return p.currentProjectAdminAccountByToken(r, token)
}

func (p *AdminAccountPlugin) currentProjectAdminAccountByToken(r *http.Request, token string) (accountRecord, []string, sessionAccountState) {
	acc, roles, state, err := p.getAccountByProjectAdminSessionState(r.Context(), token)
	if err != nil {
		return accountRecord{}, nil, sessionMissing
	}
	return acc, roles, state
}

func (p *AdminAccountPlugin) requireAccountManageToken(w http.ResponseWriter, r *http.Request, token string, invalidCode, deniedCode, failureCode int) (accountRecord, bool) {
	acc, roles, state := p.currentAccountByAnySessionToken(r, token)
	if state == sessionMissing && strings.TrimSpace(token) == "" {
		acc, roles, state = p.currentProjectAdminAccount(r)
	}
	if state != sessionAccountOK {
		writeJSON(w, invalidCode, nil, "未登录")
		return accountRecord{}, false
	}
	if acc.Status != "enabled" {
		writeJSON(w, invalidCode, nil, "未登录")
		return accountRecord{}, false
	}
	if acc.IsSuperAdmin {
		return acc, true
	}
	matched, err := p.matchedRoleIDsForPermission(r, roles, "admin_account.manage")
	if err != nil {
		writeJSON(w, failureCode, nil, "账号管理权限校验失败")
		return accountRecord{}, false
	}
	if len(matched) > 0 {
		return acc, true
	}
	writeJSON(w, deniedCode, nil, "无账号管理权限")
	return accountRecord{}, false
}

func validAccount(account string) bool {
	return len(account) >= 4 && len(account) <= 32
}

func validPassword(password string) bool {
	return len(password) >= 6 && len(password) <= 32
}

func validUUID(id string) bool {
	return uuidRE.MatchString(strings.TrimSpace(id))
}

func validRecordID(id string) bool {
	id = strings.TrimSpace(id)
	return validUUID(id) || recordIDRE.MatchString(id)
}

func validPermissionCode(code string) bool {
	return permissionCodeRE.MatchString(code)
}

func validListFilters(status, keyword string) bool {
	return (status == "" || status == "enabled" || status == "disabled") && len(keyword) <= 32
}

func (p *AdminAccountPlugin) accountDetailResponse(r *http.Request, acc accountRecord, roleIDs []string) (map[string]any, error) {
	roles, _, err := p.roleDetailsAndPermissions(r, roleIDs)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"account_id":     acc.ID,
		"account":        acc.Username,
		"status":         acc.Status,
		"is_super_admin": acc.IsSuperAdmin,
		"roles":          roles,
		"created_at":     acc.CreatedAt.Format(time.RFC3339),
		"updated_at":     acc.UpdatedAt.Format(time.RFC3339),
	}, nil
}

func (p *AdminAccountPlugin) accountPermissionResponse(r *http.Request, acc accountRecord, roleIDs []string) (map[string]any, error) {
	if acc.IsSuperAdmin {
		return map[string]any{
			"account_id":       acc.ID,
			"account":          acc.Username,
			"status":           acc.Status,
			"is_super_admin":   true,
			"roles":            []map[string]any{},
			"permission_codes": []string{},
		}, nil
	}
	roles, permissions, err := p.roleDetailsAndPermissions(r, roleIDs)
	if err != nil {
		return nil, err
	}
	if len(roles) != 1 || roles[0].RoleStatus != "enabled" {
		return nil, errNoValidAccountRole
	}
	return map[string]any{
		"account_id":       acc.ID,
		"account":          acc.Username,
		"status":           acc.Status,
		"is_super_admin":   acc.IsSuperAdmin,
		"roles":            roles,
		"permission_codes": permissions,
	}, nil
}
