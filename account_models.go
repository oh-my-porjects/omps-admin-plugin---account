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

const (
	rootAccountID     = "00000000-0000-0000-0000-000000000001"
	rootUsername      = "root"
	operatorAccountID = "00000000-0000-0000-0000-000000000002"
	rootRoleID        = "00000000-0000-0000-0000-000000000001"
	supportRoleID     = "00000000-0000-0000-0000-000000000003"
	rootPermID        = "00000000-0000-0000-0000-000000000002"
)
