package main

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
)

type sessionAccountState int

const (
	sessionMissing sessionAccountState = iota
	sessionAccountMissing
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
	if in == nil {
		writeJSON(w, formatCode, nil, "角色参数非法")
		return nil, false
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, roleID := range in {
		roleID = strings.TrimSpace(roleID)
		if roleID == "" {
			writeJSON(w, formatCode, nil, "角色参数非法")
			return nil, false
		}
		if seen[roleID] {
			continue
		}
		if !uuidRE.MatchString(roleID) {
			writeJSON(w, formatCode, nil, "角色参数非法")
			return nil, false
		}
		seen[roleID] = true
		out = append(out, roleID)
	}
	sort.Strings(out)
	available, err := p.rolesAvailable(r, out)
	if err != nil || !available {
		writeJSON(w, unavailableCode, nil, "角色不存在或已停用")
		return nil, false
	}
	return out, true
}
