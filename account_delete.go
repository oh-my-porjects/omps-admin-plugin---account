package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

func (p *AdminAccountPlugin) handleAccountDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OperatorSessionToken string `json:"operator_session_token"`
		AccountID            string `json:"account_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 2291, nil, "请求体解析失败")
		return
	}
	operator, ok := p.requireAccountManageToken(w, r, req.OperatorSessionToken, 2291, 2292, 2297)
	if !ok {
		return
	}
	req.AccountID = strings.TrimSpace(req.AccountID)
	if !validRecordID(req.AccountID) {
		writeJSON(w, 2293, nil, "account_id 参数非法")
		return
	}
	target, _, exists, err := p.getAccountByID(r.Context(), req.AccountID)
	if err != nil {
		writeJSON(w, 2297, nil, "删除账号失败")
		return
	}
	if !exists {
		writeJSON(w, 2294, nil, "账号不存在")
		return
	}
	if target.ID == operator.ID {
		writeJSON(w, 2295, nil, "当前账号不能删除自己")
		return
	}
	if target.IsSuperAdmin && !operator.IsSuperAdmin {
		writeJSON(w, 2296, nil, "普通后台账号不能删除超级管理员账号")
		return
	}
	deleted, err := p.deleteAccount(r.Context(), req.AccountID)
	if err != nil {
		writeJSON(w, 2297, nil, "删除账号失败")
		return
	}
	if !deleted {
		writeJSON(w, 2294, nil, "账号不存在")
		return
	}
	writeJSON(w, 0, nil, "ok")
}
