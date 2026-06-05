package main

import (
	"context"
	"database/sql"
	"strings"
)

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
