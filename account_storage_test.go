package main

import (
	"context"
	"database/sql"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestGetAccountByProjectAdminSessionAllowsAdminWhenAccountMissing(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	p := &AdminAccountPlugin{db: db}
	mock.ExpectQuery(regexp.QuoteMeta("SELECT COALESCE(account_id, ''), COALESCE(role_name, '')")).
		WithArgs("project-session").
		WillReturnRows(sqlmock.NewRows([]string{"account_id", "role_name"}).AddRow("pD1BjYBEQbEc", "admin"))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id::text, account, password_hash, status, is_super_admin, created_at, updated_at")).
		WithArgs("pD1BjYBEQbEc").
		WillReturnError(sql.ErrNoRows)

	acc, roles, state, err := p.getAccountByProjectAdminSessionState(context.Background(), "project-session", "")
	if err != nil {
		t.Fatalf("getAccountByProjectAdminSessionState: %v", err)
	}
	if state != sessionAccountOK {
		t.Fatalf("state=%d, want %d", state, sessionAccountOK)
	}
	if !acc.IsSuperAdmin || acc.ID != "pD1BjYBEQbEc" || acc.Status != "enabled" {
		t.Fatalf("fallback account=%#v", acc)
	}
	if len(roles) != 0 {
		t.Fatalf("roles=%#v, want empty", roles)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}
