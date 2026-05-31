package main

import (
	"encoding/json"
	"net/http"
	"time"
)

func (p *AdminAccountPlugin) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OperatorSessionToken string `json:"operator_session_token"`
		AccountID            string `json:"account_id"`
		NewPassword          string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 2261, nil, "请求体解析失败")
		return
	}
	operator, ok := p.requireAccountManageToken(w, r, req.OperatorSessionToken, 2261, 2262, 2267)
	if !ok {
		return
	}
	if !validRecordID(req.AccountID) {
		writeJSON(w, 2263, nil, "account_id 参数非法")
		return
	}
	if !validPassword(req.NewPassword) {
		writeJSON(w, 2265, nil, "密码参数非法")
		return
	}
	target, _, exists, err := p.getAccountByID(r.Context(), req.AccountID)
	if err != nil {
		writeJSON(w, 2267, nil, "重置密码失败")
		return
	}
	if !exists {
		writeJSON(w, 2264, nil, "账号不存在")
		return
	}
	if target.IsSuperAdmin && !operator.IsSuperAdmin {
		writeJSON(w, 2266, nil, "普通后台账号不能重置超级管理员密码")
		return
	}
	acc, exists, err := p.resetPassword(r.Context(), req.AccountID, req.NewPassword)
	if err != nil {
		writeJSON(w, 2267, nil, "重置密码失败")
		return
	}
	if !exists {
		writeJSON(w, 2264, nil, "账号不存在")
		return
	}
	writeJSON(w, 0, map[string]any{"account_id": req.AccountID, "updated_at": acc.UpdatedAt.Format(time.RFC3339)}, "ok")
}
