package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"
)

var errAccountNotFound = errors.New("account not found")

func (p *AdminAccountPlugin) initStorage(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if p.db == nil {
		p.ensureMemoryStore()
		return nil
	}
	for _, stmt := range []string{
		`CREATE EXTENSION IF NOT EXISTS pgcrypto`,
		`CREATE OR REPLACE FUNCTION generate_short_id() RETURNS TEXT AS $$
		DECLARE
			chars TEXT := 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
			bytes BYTEA := gen_random_bytes(12);
			result TEXT := '';
			i INT;
		BEGIN
			FOR i IN 0..11 LOOP
				result := result || substr(chars, 1 + (get_byte(bytes, i) % 62), 1);
			END LOOP;
			RETURN result;
		END;
		$$ LANGUAGE plpgsql VOLATILE`,
		`CREATE TABLE IF NOT EXISTS account_accounts (
			id TEXT PRIMARY KEY DEFAULT generate_short_id(),
			account TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'enabled',
			is_super_admin BOOLEAN NOT NULL DEFAULT FALSE,
			is_temporary BOOLEAN NOT NULL DEFAULT FALSE,
			expires_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`ALTER TABLE IF EXISTS account_role_bindings DROP CONSTRAINT IF EXISTS account_role_bindings_account_id_fkey`,
		`ALTER TABLE account_accounts ALTER COLUMN id DROP DEFAULT`,
		`ALTER TABLE account_accounts ALTER COLUMN id TYPE TEXT USING id::text`,
		`ALTER TABLE account_accounts ALTER COLUMN id SET DEFAULT generate_short_id()`,
		// 兼容老表：把 is_temporary / expires_at 字段补上
		`ALTER TABLE account_accounts ADD COLUMN IF NOT EXISTS is_temporary BOOLEAN NOT NULL DEFAULT FALSE`,
		`ALTER TABLE account_accounts ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ`,
		`CREATE TABLE IF NOT EXISTS account_role_bindings (
			id TEXT PRIMARY KEY DEFAULT generate_short_id(),
			account_id TEXT NOT NULL REFERENCES account_accounts(id) ON DELETE CASCADE,
			role_id TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			UNIQUE (account_id, role_id)
		)`,
		`ALTER TABLE account_role_bindings DROP CONSTRAINT IF EXISTS account_role_bindings_account_id_fkey`,
		`ALTER TABLE account_role_bindings ALTER COLUMN id DROP DEFAULT`,
		`ALTER TABLE account_role_bindings ALTER COLUMN id TYPE TEXT USING id::text`,
		`ALTER TABLE account_role_bindings ALTER COLUMN id SET DEFAULT generate_short_id()`,
		`ALTER TABLE account_role_bindings ALTER COLUMN account_id TYPE TEXT USING account_id::text`,
		`ALTER TABLE account_role_bindings ALTER COLUMN role_id TYPE TEXT USING role_id::text`,
		`DO $$
		BEGIN
			IF NOT EXISTS (
				SELECT 1 FROM pg_indexes
				WHERE schemaname = current_schema()
				  AND indexname = 'account_role_bindings_one_role_per_account_idx'
			) AND NOT EXISTS (
				SELECT 1 FROM account_role_bindings
				GROUP BY account_id
				HAVING COUNT(*) > 1
			) THEN
				CREATE UNIQUE INDEX account_role_bindings_one_role_per_account_idx
				ON account_role_bindings (account_id);
			END IF;
		END;
		$$`,
		`DO $$
		BEGIN
			IF NOT EXISTS (
				SELECT 1 FROM pg_constraint
				WHERE conname = 'account_role_bindings_account_id_fkey'
				  AND conrelid = 'account_role_bindings'::regclass
			) THEN
				ALTER TABLE account_role_bindings
				ADD CONSTRAINT account_role_bindings_account_id_fkey
				FOREIGN KEY (account_id) REFERENCES account_accounts(id) ON DELETE CASCADE NOT VALID;
			END IF;
		END;
		$$`,
		// 临时超管账号种子记录（task/inner_plugin.md §4.4 § §6.1）
		// 项目级唯一一条 is_temporary=true 的记录，初始 disabled
		// admin-server 调 _create-temporary-admin 接口时只重置 account/password_hash/status/expires_at，ID 永远不变
		`INSERT INTO account_accounts (id, account, password_hash, status, is_super_admin, is_temporary)
		 VALUES ('00000000-0000-0000-0000-0000000000fe', '__temporary_super_admin_seed__', '', 'disabled', TRUE, TRUE)
		 ON CONFLICT (id) DO NOTHING`,
	} {
		if _, err := p.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

func (p *AdminAccountPlugin) ensureMemoryStore() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.accounts == nil {
		p.accounts = map[string]accountRecord{}
	}
	if p.roles == nil {
		p.roles = map[string][]string{}
	}
}

func (p *AdminAccountPlugin) getAccountByID(ctx context.Context, accountID string) (accountRecord, []string, bool, error) {
	accountID = strings.TrimSpace(accountID)
	if p.db != nil {
		acc, ok, err := p.queryAccount(ctx, "id::text=$1", accountID)
		if err != nil || !ok {
			return acc, nil, ok, err
		}
		roles, err := p.accountRoleIDs(ctx, acc.ID)
		if err != nil {
			return acc, nil, true, err
		}
		roles, err = p.normalizeAccountRoles(ctx, nil, acc.ID, roles)
		return acc, roles, true, err
	}
	p.mu.Lock()
	acc, ok := p.accounts[accountID]
	roles := append([]string(nil), p.roles[accountID]...)
	p.mu.Unlock()
	if !ok {
		return acc, nil, false, nil
	}
	roles, err := p.normalizeAccountRoles(ctx, nil, acc.ID, roles)
	return acc, roles, true, err
}

func (p *AdminAccountPlugin) getAccountByAccount(ctx context.Context, account string) (accountRecord, []string, bool, error) {
	if p.db != nil {
		acc, ok, err := p.queryAccount(ctx, "account=$1", account)
		if err != nil || !ok {
			return acc, nil, ok, err
		}
		roles, err := p.accountRoleIDs(ctx, acc.ID)
		if err != nil {
			return acc, nil, true, err
		}
		roles, err = p.normalizeAccountRoles(ctx, nil, acc.ID, roles)
		return acc, roles, true, err
	}
	p.mu.Lock()
	for _, acc := range p.accounts {
		if acc.Username == account {
			roles := append([]string(nil), p.roles[acc.ID]...)
			p.mu.Unlock()
			roles, err := p.normalizeAccountRoles(ctx, nil, acc.ID, roles)
			return acc, roles, true, err
		}
	}
	p.mu.Unlock()
	return accountRecord{}, nil, false, nil
}

func (p *AdminAccountPlugin) queryAccount(ctx context.Context, where string, arg any) (accountRecord, bool, error) {
	var acc accountRecord
	err := p.db.QueryRowContext(ctx, `
		SELECT id::text, account, password_hash, status, is_super_admin, created_at, updated_at
		FROM account_accounts WHERE `+where, arg).
		Scan(&acc.ID, &acc.Username, &acc.PasswordHash, &acc.Status, &acc.IsSuperAdmin, &acc.CreatedAt, &acc.UpdatedAt)
	if sqlNoRows(err) {
		return accountRecord{}, false, nil
	}
	if err != nil {
		return accountRecord{}, false, err
	}
	return acc, true, nil
}

func (p *AdminAccountPlugin) accountRoleIDs(ctx context.Context, accountID string) ([]string, error) {
	if p.db == nil {
		p.mu.Lock()
		defer p.mu.Unlock()
		return append([]string(nil), p.roles[accountID]...), nil
	}
	rows, err := p.db.QueryContext(ctx, "SELECT role_id::text FROM account_role_bindings WHERE account_id::text=$1 ORDER BY created_at, id::text", accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (p *AdminAccountPlugin) createAccount(ctx context.Context, account, password, status string, roleIDs []string) (accountRecord, []string, error) {
	now := time.Now().UTC()
	passwordHash, err := hashPassword(password)
	if err != nil {
		return accountRecord{}, nil, err
	}
	if p.db != nil {
		tx, err := p.db.BeginTx(ctx, nil)
		if err != nil {
			return accountRecord{}, nil, err
		}
		defer tx.Rollback()

		var acc accountRecord
		err = tx.QueryRowContext(ctx, `
			INSERT INTO account_accounts (account, password_hash, status, is_super_admin)
			VALUES ($1, $2, $3, FALSE)
			RETURNING id::text, account, password_hash, status, is_super_admin, created_at, updated_at`,
			account, passwordHash, status).
			Scan(&acc.ID, &acc.Username, &acc.PasswordHash, &acc.Status, &acc.IsSuperAdmin, &acc.CreatedAt, &acc.UpdatedAt)
		if err != nil {
			return accountRecord{}, nil, err
		}
		if err := p.replaceAccountRolesTx(ctx, tx, acc.ID, roleIDs); err != nil {
			return accountRecord{}, nil, err
		}
		if err := tx.Commit(); err != nil {
			return accountRecord{}, nil, err
		}
		return acc, roleIDs, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	acc := accountRecord{ID: newShortID(), Username: account, PasswordHash: passwordHash, Status: status, CreatedAt: now, UpdatedAt: now}
	p.accounts[acc.ID] = acc
	p.roles[acc.ID] = append([]string(nil), roleIDs...)
	return acc, roleIDs, nil
}

func (p *AdminAccountPlugin) listAccounts(ctx context.Context, status, keyword string, page, pageSize int) ([]accountResponse, int, error) {
	if p.db != nil {
		where, args := "TRUE", []any{}
		if status != "" {
			args = append(args, status)
			where += " AND status=$" + strconv.Itoa(len(args))
		}
		if keyword != "" {
			args = append(args, "%"+keyword+"%")
			where += " AND lower(account) LIKE $" + strconv.Itoa(len(args))
		}
		var total int
		if err := p.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM account_accounts WHERE "+where, args...).Scan(&total); err != nil {
			return nil, 0, err
		}
		args = append(args, pageSize, (page-1)*pageSize)
		rows, err := p.db.QueryContext(ctx, `
			SELECT id::text, account, password_hash, status, is_super_admin, created_at, updated_at
			FROM account_accounts WHERE `+where+` ORDER BY created_at DESC LIMIT $`+strconv.Itoa(len(args)-1)+` OFFSET $`+strconv.Itoa(len(args)), args...)
		if err != nil {
			return nil, 0, err
		}
		defer rows.Close()
		items := []accountResponse{}
		for rows.Next() {
			var acc accountRecord
			if err := rows.Scan(&acc.ID, &acc.Username, &acc.PasswordHash, &acc.Status, &acc.IsSuperAdmin, &acc.CreatedAt, &acc.UpdatedAt); err != nil {
				return nil, 0, err
			}
			roles, err := p.accountRoleIDs(ctx, acc.ID)
			if err != nil {
				return nil, 0, err
			}
			roles, err = p.normalizeAccountRoles(ctx, nil, acc.ID, roles)
			if err != nil && !errors.Is(err, errNoValidAccountRole) {
				return nil, 0, err
			}
			items = append(items, accountToResponse(acc, roles))
		}
		return items, total, rows.Err()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	all := make([]accountResponse, 0, len(p.accounts))
	for _, acc := range p.accounts {
		if status != "" && acc.Status != status {
			continue
		}
		if keyword != "" && !strings.Contains(strings.ToLower(acc.Username), keyword) {
			continue
		}
		roles := append([]string(nil), p.roles[acc.ID]...)
		if len(roles) > 1 {
			roles = roles[:1]
		}
		all = append(all, accountToResponse(acc, roles))
	}
	sort.Slice(all, func(i, j int) bool { return all[i].CreatedAt > all[j].CreatedAt })
	total := len(all)
	start := (page - 1) * pageSize
	if start > total {
		start = total
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	return all[start:end], total, nil
}

func (p *AdminAccountPlugin) updateAccount(ctx context.Context, accountID, status string, roleIDs []string) (accountRecord, []string, bool, error) {
	if p.db != nil {
		tx, err := p.db.BeginTx(ctx, nil)
		if err != nil {
			return accountRecord{}, nil, false, err
		}
		defer tx.Rollback()

		var acc accountRecord
		err = tx.QueryRowContext(ctx, `
			UPDATE account_accounts SET status=$2, updated_at=now()
			WHERE id::text=$1
			RETURNING id::text, account, password_hash, status, is_super_admin, created_at, updated_at`, accountID, status).
			Scan(&acc.ID, &acc.Username, &acc.PasswordHash, &acc.Status, &acc.IsSuperAdmin, &acc.CreatedAt, &acc.UpdatedAt)
		if sqlNoRows(err) {
			return accountRecord{}, nil, false, nil
		}
		if err != nil {
			return accountRecord{}, nil, false, err
		}
		if err := p.replaceAccountRolesTx(ctx, tx, acc.ID, roleIDs); err != nil {
			return accountRecord{}, nil, false, err
		}
		if err := tx.Commit(); err != nil {
			return accountRecord{}, nil, false, err
		}
		return acc, roleIDs, true, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	acc, ok := p.accounts[accountID]
	if !ok {
		return accountRecord{}, nil, false, nil
	}
	acc.Status = status
	acc.UpdatedAt = time.Now().UTC()
	p.accounts[acc.ID] = acc
	p.roles[acc.ID] = append([]string(nil), roleIDs...)
	return acc, roleIDs, true, nil
}

func (p *AdminAccountPlugin) replaceAccountRoles(ctx context.Context, accountID string, roleIDs []string) error {
	if p.db == nil {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.roles[accountID] = append([]string(nil), roleIDs...)
		return nil
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := p.replaceAccountRolesTx(ctx, tx, accountID, roleIDs); err != nil {
		return err
	}
	return tx.Commit()
}

func (p *AdminAccountPlugin) replaceAccountRolesTx(ctx context.Context, tx *sql.Tx, accountID string, roleIDs []string) error {
	if _, err := tx.ExecContext(ctx, "DELETE FROM account_role_bindings WHERE account_id::text=$1", accountID); err != nil {
		return err
	}
	for _, roleID := range roleIDs {
		if _, err := tx.ExecContext(ctx, "INSERT INTO account_role_bindings (account_id, role_id) VALUES ($1, $2)", accountID, roleID); err != nil {
			return err
		}
	}
	return nil
}

func (p *AdminAccountPlugin) normalizeAccountRoles(ctx context.Context, tx *sql.Tx, accountID string, roleIDs []string) ([]string, error) {
	if len(roleIDs) <= 1 {
		if len(roleIDs) == 1 && strings.TrimSpace(roleIDs[0]) != "" {
			return []string{strings.TrimSpace(roleIDs[0])}, nil
		}
		return []string{}, errNoValidAccountRole
	}
	for _, roleID := range roleIDs {
		roleID = strings.TrimSpace(roleID)
		if roleID == "" {
			continue
		}
		detail, ok, err := p.adminRoleDetail(ctx, nil, roleID)
		if err != nil {
			return nil, err
		}
		if !ok || normalizeRoleStatus(detail) != "enabled" {
			continue
		}
		if err := p.keepOnlyAccountRole(ctx, tx, accountID, roleID); err != nil {
			return nil, err
		}
		return []string{roleID}, nil
	}
	return []string{}, errNoValidAccountRole
}

func (p *AdminAccountPlugin) keepOnlyAccountRole(ctx context.Context, tx *sql.Tx, accountID, roleID string) error {
	if p.db == nil {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.roles[accountID] = []string{roleID}
		return nil
	}
	if tx != nil {
		_, err := tx.ExecContext(ctx, "DELETE FROM account_role_bindings WHERE account_id::text=$1 AND role_id::text<>$2", accountID, roleID)
		return err
	}
	_, err := p.db.ExecContext(ctx, "DELETE FROM account_role_bindings WHERE account_id::text=$1 AND role_id::text<>$2", accountID, roleID)
	return err
}

func (p *AdminAccountPlugin) resetPassword(ctx context.Context, accountID, newPassword string) (accountRecord, bool, error) {
	passwordHash, err := hashPassword(newPassword)
	if err != nil {
		return accountRecord{}, false, err
	}
	if p.db != nil {
		var acc accountRecord
		err := p.db.QueryRowContext(ctx, `
			UPDATE account_accounts SET password_hash=$2, updated_at=now()
			WHERE id::text=$1
			RETURNING id::text, account, password_hash, status, is_super_admin, created_at, updated_at`,
			accountID, passwordHash).
			Scan(&acc.ID, &acc.Username, &acc.PasswordHash, &acc.Status, &acc.IsSuperAdmin, &acc.CreatedAt, &acc.UpdatedAt)
		if sqlNoRows(err) {
			return accountRecord{}, false, nil
		}
		return acc, err == nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	acc, ok := p.accounts[accountID]
	if !ok {
		return accountRecord{}, false, nil
	}
	acc.PasswordHash = passwordHash
	acc.UpdatedAt = time.Now().UTC()
	p.accounts[acc.ID] = acc
	return acc, true, nil
}

func sessionRedisKey(token string) string {
	return "admin_accounts:session:" + token
}

func hashPassword(password string) (string, error) {
	sum := sha256.Sum256([]byte(password))
	return hex.EncodeToString(sum[:]), nil
}

func verifyPassword(hash, password string) bool {
	expected, err := hashPassword(password)
	return err == nil && hash == expected
}

func accountToResponse(acc accountRecord, roles []string) accountResponse {
	return accountResponse{
		AccountID: acc.ID, Account: acc.Username,
		Status: acc.Status, RoleIDs: append([]string(nil), roles...), IsSuperAdmin: acc.IsSuperAdmin,
		CreatedAt: acc.CreatedAt.Format(time.RFC3339), UpdatedAt: acc.UpdatedAt.Format(time.RFC3339),
	}
}

func normalizeStatus(status string) string {
	status = strings.TrimSpace(status)
	if status == "enabled" || status == "disabled" {
		return status
	}
	return ""
}

func sqlNoRows(err error) bool {
	return errors.Is(err, sql.ErrNoRows)
}
