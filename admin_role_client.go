package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

type adminRoleAPIResponse struct {
	Status int             `json:"status"`
	Data   json.RawMessage `json:"data"`
}

type adminRolePermission struct {
	Code string `json:"code"`
}

type adminRoleDetail struct {
	RoleID      string                `json:"role_id"`
	Status      string                `json:"status"`
	DeletedAt   string                `json:"deleted_at"`
	Permissions []adminRolePermission `json:"permissions"`
}

type adminRoleCheckPermission struct {
	Allowed    bool   `json:"allowed"`
	RoleStatus string `json:"role_status"`
}

func (p *AdminAccountPlugin) rolesAvailable(r *http.Request, roleIDs []string) (bool, error) {
	if len(roleIDs) == 0 {
		return true, nil
	}
	for _, roleID := range roleIDs {
		detail, ok, err := p.adminRoleDetail(r.Context(), r, roleID)
		if err != nil {
			return false, err
		}
		if !ok || normalizeRoleStatus(detail) != "enabled" {
			return false, nil
		}
	}
	return true, nil
}

func (p *AdminAccountPlugin) matchedRoleIDsForPermission(r *http.Request, roleIDs []string, permissionCode string) ([]string, error) {
	matched, _, err := p.evaluateRolePermission(r, roleIDs, permissionCode)
	return matched, err
}

func (p *AdminAccountPlugin) evaluateRolePermission(r *http.Request, roleIDs []string, permissionCode string) ([]string, []accountRoleResponse, error) {
	matched := []string{}
	roles := make([]accountRoleResponse, 0, len(roleIDs))
	hasInvalidRole := false
	for _, roleID := range roleIDs {
		detail, ok, err := p.adminRoleDetail(r.Context(), r, roleID)
		if err != nil {
			return nil, nil, err
		}
		status := "missing"
		if ok {
			status = normalizeRoleStatus(detail)
		}
		roles = append(roles, accountRoleResponse{RoleID: roleID, RoleStatus: status})
		if status != "enabled" {
			hasInvalidRole = true
			continue
		}
		allowed, roleStatus, err := p.adminRoleCheckPermission(r.Context(), r, roleID, permissionCode)
		if err != nil {
			return nil, nil, err
		}
		if roleStatus != "" && roleStatus != "enabled" {
			roles[len(roles)-1].RoleStatus = roleStatus
			hasInvalidRole = true
			continue
		}
		if allowed {
			matched = append(matched, roleID)
		}
	}
	if hasInvalidRole {
		return []string{}, roles, nil
	}
	return matched, roles, nil
}

func (p *AdminAccountPlugin) roleDetailsAndPermissions(r *http.Request, roleIDs []string) ([]accountRoleResponse, []string, error) {
	roles := make([]accountRoleResponse, 0, len(roleIDs))
	permSet := map[string]bool{}
	for _, roleID := range roleIDs {
		detail, ok, err := p.adminRoleDetail(r.Context(), r, roleID)
		if err != nil {
			return nil, nil, err
		}
		status := "missing"
		if ok {
			status = normalizeRoleStatus(detail)
		}
		roles = append(roles, accountRoleResponse{RoleID: roleID, RoleStatus: status})
		if status != "enabled" {
			continue
		}
		for _, perm := range detail.Permissions {
			permSet[perm.Code] = true
		}
	}
	permissions := make([]string, 0, len(permSet))
	for code := range permSet {
		permissions = append(permissions, code)
	}
	sort.Strings(permissions)
	return roles, permissions, nil
}

func (p *AdminAccountPlugin) adminRoleDetail(ctx context.Context, r *http.Request, roleID string) (adminRoleDetail, bool, error) {
	target := "/api/role/detail?role_id=" + url.QueryEscape(roleID)
	var resp adminRoleAPIResponse
	if err := p.doAdminRoleRequest(ctx, r, http.MethodGet, target, nil, &resp); err != nil {
		return adminRoleDetail{}, false, err
	}
	if resp.Status == 2122 || resp.Status == 2312 || resp.Status == 2322 || resp.Status == 2332 || resp.Status == 2342 {
		return adminRoleDetail{}, false, nil
	}
	if resp.Status != 0 {
		return adminRoleDetail{}, false, errors.New("admin_role detail failed")
	}
	var detail adminRoleDetail
	if err := json.Unmarshal(resp.Data, &detail); err != nil {
		return adminRoleDetail{}, false, err
	}
	return detail, true, nil
}

func (p *AdminAccountPlugin) adminRoleCheckPermission(ctx context.Context, r *http.Request, roleID, permissionCode string) (bool, string, error) {
	body := map[string]string{"role_id": roleID, "permission_code": permissionCode}
	var resp adminRoleAPIResponse
	if err := p.doAdminRoleRequest(ctx, r, http.MethodPost, "/api/role/check-permission", body, &resp); err != nil {
		return false, "", err
	}
	if resp.Status == 2173 {
		return false, "missing", nil
	}
	if resp.Status == 2174 {
		return false, "enabled", nil
	}
	if resp.Status != 0 {
		return false, "", errors.New("admin_role permission check failed")
	}
	var data adminRoleCheckPermission
	if err := json.Unmarshal(resp.Data, &data); err != nil {
		return false, "", err
	}
	status := strings.TrimSpace(data.RoleStatus)
	if status == "" {
		status = "enabled"
	}
	return data.Allowed && status == "enabled", status, nil
}

func normalizeRoleStatus(detail adminRoleDetail) string {
	status := strings.TrimSpace(detail.Status)
	if status == "deleted" {
		return "deleted"
	}
	if strings.TrimSpace(detail.DeletedAt) != "" {
		return "deleted"
	}
	if status == "" {
		return "missing"
	}
	return status
}

func (p *AdminAccountPlugin) doAdminRoleRequest(ctx context.Context, r *http.Request, method, target string, body any, out any) error {
	if p.internalRequest == nil {
		return errors.New("runtime internal request bridge unavailable")
	}
	var payload []byte
	if body == nil {
		payload = nil
	} else {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = raw
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	headers := make(http.Header)
	if r != nil {
		headers = r.Header.Clone()
	}
	if body != nil {
		headers.Set("Content-Type", "application/json")
	}
	if p.adminAPIKey != "" {
		headers.Set("X-API-Key", p.adminAPIKey)
	}
	status, _, responseBody, err := p.internalRequest(ctx, method, target, payload, headers)
	if err != nil {
		return err
	}
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		return errors.New("admin_role api http status failed")
	}
	return json.Unmarshal(responseBody, out)
}
