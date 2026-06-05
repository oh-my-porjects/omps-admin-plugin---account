package main

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
)

var errNoValidAccountRole = errors.New("account has no enabled role")

type sessionAccountState int

const (
	sessionMissing sessionAccountState = iota
	sessionAccountMissing
	sessionAccountInvalidRole
	sessionAccountOK
)

func parsePage(r *http.Request) (int, int, bool) {
	rawPage := r.URL.Query().Get("page")
	rawPageSize := r.URL.Query().Get("page_size")
	if rawPage == "" || rawPageSize == "" {
		return 0, 0, false
	}
	page, err1 := strconv.Atoi(rawPage)
	pageSize, err2 := strconv.Atoi(rawPageSize)
	if err1 != nil || err2 != nil || page < 1 || pageSize < 1 || pageSize > 100 {
		return 0, 0, false
	}
	return page, pageSize, true
}

func (p *AdminAccountPlugin) cleanAndValidateRoles(w http.ResponseWriter, r *http.Request, in []string, formatCode, unavailableCode int) ([]string, bool) {
	if len(in) != 1 {
		writeJSON(w, formatCode, nil, "角色参数非法")
		return nil, false
	}
	roleID := strings.TrimSpace(in[0])
	if roleID == "" || !validRecordID(roleID) {
		writeJSON(w, formatCode, nil, "角色参数非法")
		return nil, false
	}
	out := []string{roleID}
	available, err := p.rolesAvailable(r, out)
	if err != nil || !available {
		writeJSON(w, unavailableCode, nil, "角色不存在或已停用")
		return nil, false
	}
	return out, true
}
