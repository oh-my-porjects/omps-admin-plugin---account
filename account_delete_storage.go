package main

import (
	"context"
	"strings"
)

func (p *AdminAccountPlugin) deleteAccount(ctx context.Context, accountID string) (bool, error) {
	accountID = strings.TrimSpace(accountID)
	if p.db != nil {
		tx, err := p.db.BeginTx(ctx, nil)
		if err != nil {
			return false, err
		}
		defer tx.Rollback()
		if _, err := tx.ExecContext(ctx, "DELETE FROM account_role_bindings WHERE account_id::text=$1", accountID); err != nil {
			return false, err
		}
		res, err := tx.ExecContext(ctx, "DELETE FROM account_accounts WHERE id::text=$1", accountID)
		if err != nil {
			return false, err
		}
		affected, err := res.RowsAffected()
		if err != nil {
			return false, err
		}
		if affected == 0 {
			return false, nil
		}
		if err := tx.Commit(); err != nil {
			return false, err
		}
		return true, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.accounts[accountID]; !ok {
		return false, nil
	}
	delete(p.accounts, accountID)
	delete(p.roles, accountID)
	return true, nil
}
