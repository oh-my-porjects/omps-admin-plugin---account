package main

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

func (p *AdminAccountPlugin) createSession(ctx context.Context, accountID string) (string, time.Time, error) {
	token := newToken()
	expiresAt := time.Now().UTC().Add(p.sessionTTL)
	if p.rdb == nil {
		return "", time.Time{}, errors.New("redis unavailable")
	}
	key := sessionRedisKey(token)
	if err := p.rdb.HSet(ctx, key, map[string]any{
		"account_id": accountID,
		"expires_at": expiresAt.Format(time.RFC3339),
		"created_at": time.Now().UTC().Format(time.RFC3339),
	}).Err(); err != nil {
		return "", time.Time{}, err
	}
	if err := p.rdb.Expire(ctx, key, p.sessionTTL).Err(); err != nil {
		return "", time.Time{}, err
	}
	return token, expiresAt, nil
}

func (p *AdminAccountPlugin) getAccountBySession(ctx context.Context, token string) (accountRecord, []string, bool, error) {
	if p.rdb == nil {
		return accountRecord{}, nil, false, nil
	}
	accountID, err := p.rdb.HGet(ctx, sessionRedisKey(token), "account_id").Result()
	if errors.Is(err, redis.Nil) {
		return accountRecord{}, nil, false, nil
	}
	if err != nil {
		return accountRecord{}, nil, false, err
	}
	return p.getAccountByID(ctx, accountID)
}

func (p *AdminAccountPlugin) getAccountBySessionState(ctx context.Context, token string) (accountRecord, []string, sessionAccountState, error) {
	if p.rdb == nil {
		return accountRecord{}, nil, sessionMissing, nil
	}
	accountID, err := p.rdb.HGet(ctx, sessionRedisKey(token), "account_id").Result()
	if errors.Is(err, redis.Nil) {
		return accountRecord{}, nil, sessionMissing, nil
	}
	if err != nil {
		return accountRecord{}, nil, sessionMissing, err
	}
	acc, roles, ok, err := p.getAccountByID(ctx, accountID)
	if err != nil {
		if errors.Is(err, errNoValidAccountRole) {
			return acc, roles, sessionAccountOK, nil
		}
		return accountRecord{}, nil, sessionMissing, err
	}
	if !ok {
		return accountRecord{}, nil, sessionAccountMissing, nil
	}
	return acc, roles, sessionAccountOK, nil
}

func (p *AdminAccountPlugin) getAccountByProjectAdminSessionState(ctx context.Context, token string) (accountRecord, []string, sessionAccountState, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return accountRecord{}, nil, sessionMissing, nil
	}
	var accountID string
	if p.lookupProjectAdminSessionAccountID != nil {
		id, err := p.lookupProjectAdminSessionAccountID(ctx, token)
		if err != nil {
			return accountRecord{}, nil, sessionMissing, err
		}
		accountID = strings.TrimSpace(id)
	} else {
		if p.db == nil {
			return accountRecord{}, nil, sessionMissing, nil
		}
		err := p.db.QueryRowContext(ctx, `
			SELECT COALESCE(account_id, '')
			FROM rt_admin_sessions
			WHERE token = $1 AND expires_at > NOW()
		`, token).Scan(&accountID)
		if sqlNoRows(err) {
			return accountRecord{}, nil, sessionMissing, nil
		}
		if err != nil {
			return accountRecord{}, nil, sessionMissing, err
		}
	}
	if accountID == "" {
		return accountRecord{}, nil, sessionAccountMissing, nil
	}
	acc, roles, ok, err := p.getAccountByID(ctx, accountID)
	if err != nil {
		if errors.Is(err, errNoValidAccountRole) {
			return acc, roles, sessionAccountOK, nil
		}
		return accountRecord{}, nil, sessionMissing, err
	}
	if !ok {
		return accountRecord{}, nil, sessionAccountMissing, nil
	}
	return acc, roles, sessionAccountOK, nil
}
