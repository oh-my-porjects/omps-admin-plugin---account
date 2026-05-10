package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
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
	Permissions []adminRolePermission `json:"permissions"`
}

type adminRoleCheckPermission struct {
	Allowed    bool   `json:"allowed"`
	RoleStatus string `json:"role_status"`
}

func (p *AdminAccountPlugin) rolesAvailable(r *http.Request, roleIDs []string) bool {
	if len(roleIDs) == 0 {
		return true
	}
	for _, roleID := range roleIDs {
		detail, ok, err := p.adminRoleDetail(r.Context(), r, roleID)
		if err != nil || !ok || detail.Status != "enabled" {
			return false
		}
	}
	return true
}

func (p *AdminAccountPlugin) matchedRoleIDsForPermission(r *http.Request, roleIDs []string, permissionCode string) ([]string, error) {
	matched := []string{}
	for _, roleID := range roleIDs {
		allowed, err := p.adminRoleCheckPermission(r.Context(), r, roleID, permissionCode)
		if err != nil {
			return nil, err
		}
		if allowed {
			matched = append(matched, roleID)
		}
	}
	return matched, nil
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
			status = detail.Status
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
	endpoint := p.runtimeURL(r, "/api/admin-role/detail") + "?role_id=" + url.QueryEscape(roleID)
	var resp adminRoleAPIResponse
	if err := p.doAdminRoleRequest(ctx, http.MethodGet, endpoint, nil, &resp); err != nil {
		return adminRoleDetail{}, false, err
	}
	if resp.Status == 2122 {
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

func (p *AdminAccountPlugin) adminRoleCheckPermission(ctx context.Context, r *http.Request, roleID, permissionCode string) (bool, error) {
	body := map[string]string{"role_id": roleID, "permission_code": permissionCode}
	var resp adminRoleAPIResponse
	if err := p.doAdminRoleRequest(ctx, http.MethodPost, p.runtimeURL(r, "/api/admin-role/check-permission"), body, &resp); err != nil {
		return false, err
	}
	if resp.Status == 2173 || resp.Status == 2174 {
		return false, nil
	}
	if resp.Status != 0 {
		return false, errors.New("admin_role permission check failed")
	}
	var data adminRoleCheckPermission
	if err := json.Unmarshal(resp.Data, &data); err != nil {
		return false, err
	}
	return data.Allowed && data.RoleStatus == "enabled", nil
}

func (p *AdminAccountPlugin) doAdminRoleRequest(ctx context.Context, method, endpoint string, body any, out any) error {
	var payload *bytes.Reader
	if body == nil {
		payload = bytes.NewReader(nil)
	} else {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = bytes.NewReader(raw)
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, endpoint, payload)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-API-Key", p.adminAPIKey)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return errors.New("admin_role api http status failed")
	}
	return json.NewDecoder(res.Body).Decode(out)
}

func (p *AdminAccountPlugin) runtimeURL(r *http.Request, path string) string {
	host := strings.TrimSpace(p.runtimeAddr)
	if host == "" && r != nil {
		host = strings.TrimSpace(r.Host)
	}
	if host == "" || host == "example.com" {
		host = "127.0.0.1:8080"
	}
	if !strings.Contains(host, "://") {
		host = "http://" + host
	}
	parsed, err := url.Parse(host)
	if err == nil && parsed.Port() == "" {
		if _, _, splitErr := net.SplitHostPort(parsed.Host); splitErr != nil {
			parsed.Host = net.JoinHostPort(parsed.Hostname(), "8080")
			host = parsed.String()
		}
	}
	host = strings.TrimRight(host, "/")
	return host + path
}
