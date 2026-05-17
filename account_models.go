package main

import "time"

type accountRecord struct {
	ID           string
	Username     string
	PasswordHash string
	DisplayName  string
	Status       string
	IsSuperAdmin bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type sessionRecord struct {
	AccountID    string
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

type accountRoleResponse struct {
	RoleID     string `json:"role_id"`
	RoleStatus string `json:"role_status"`
}

type accountResponse struct {
	AccountID    string   `json:"account_id"`
	Account      string   `json:"account"`
	Status       string   `json:"status"`
	RoleIDs      []string `json:"role_ids"`
	IsSuperAdmin bool     `json:"is_super_admin"`
	CreatedAt    string   `json:"created_at"`
	UpdatedAt    string   `json:"updated_at"`
}

// 平台短 ID 标准：12 字符 base62
// 系统预设 ID 命名：开头 8 个 0 + 4 字符语义后缀
// rootRoleID / rootPermID / supportRoleID 跟 role 公共模块对齐
const (
	rootAccountID     = "00000000RtAc"
	rootUsername      = "root"
	operatorAccountID = "00000000OpAc"
	rootRoleID        = "00000000Root"
	supportRoleID     = "00000000Supp"
	rootPermID        = "00000000SysP"
)
