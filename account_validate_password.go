package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

// handleValidatePassword 内部接口：runtime adminLogin 调用 验证账号密码 + 返回身份信息
//
// 流程：
//   1. runtime adminLogin 收到用户输入的账号 + 密码
//   2. POST /api/account/_validate-password 带 X-Internal-Token 校验
//   3. 本接口校验账号密码，返回 {account_id, is_super_admin, role_ids}
//   4. runtime 拿 role_ids 调 role 模块查 role.name 写 session
//
// 跟 handleLogin 区别：
//   - 不创建 account 模块自己的 session（runtime 自己管 session）
//   - 不需要 ADMIN_API_KEY 鉴权（走 X-Internal-Token，admin-server 配置的环境变量）
//   - 返回结构精简，只含 runtime 鉴权需要的字段
//
// 鉴权：runtime 调用时已经过 runtime 自己的 internal token 校验
// 这里不做额外鉴权（plugin 内部互调）
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
		writeJSON(w, 2281, nil, "账号或密码参数非法")
		return
	}
	acc, roles, ok, err := p.getAccountByAccount(r.Context(), req.Account)
	if err != nil {
		writeJSON(w, 2284, nil, "校验失败")
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
	// getAccountByAccount 返回的 roles 已经是 []string (role_id 列表)
	if roles == nil {
		roles = []string{}
	}
	writeJSON(w, 0, map[string]any{
		"account_id":     acc.ID,
		"account":        acc.Username,
		"is_super_admin": acc.IsSuperAdmin,
		"role_ids":       roles,
	}, "ok")
}
