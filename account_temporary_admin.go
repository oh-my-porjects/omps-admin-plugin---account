package main

// account_temporary_admin.go — 临时超管账号机制
//
// 设计意图：解决「鸡生蛋」问题 + 提供应急恢复
//   1. 项目里始终有一条 is_temporary=true 的种子记录，ID 永远不变
//   2. admin-server 通过 runtime 管理面调用 CreateTemporaryAdmin 内部方法时，只重置
//      account / password_hash / status=enabled / expires_at，ID 不变
//   3. 同时只有一条临时超管记录（不会越长越大），重复调覆盖同一条
//   4. 10 分钟后过期，后台 worker 自动 status=disabled，记录保留下次复用
//
// 信任边界：
//   - 本模块不公开生成临时超管的业务 HTTP API。
//   - runtime 先验证环境级 X-Internal-Token，再向本模块注入
//     X-Internal-Authenticated: true；本模块只接受这个受控内部方法调用。

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// 固定的临时超管账号 ID（跟 account_storage.go init 时的种子记录对齐）
const temporarySuperAdminSeedID = "00000000-0000-0000-0000-0000000000fe"

// 临时账号 TTL（10 分钟）
const temporaryAdminTTL = 10 * time.Minute

type temporaryAdminCredential struct {
	Account    string `json:"account"`
	Password   string `json:"password"`
	ExpiresAt  string `json:"expires_at"`
	TTLSeconds int    `json:"ttl_seconds"`
}

// createTemporaryAdmin 重置固定种子记录并只向受控内部调用方返回一次明文凭证。
// 调用方必须经过 runtime 管理面和模块 mux 的双重内部鉴权，不能由公开业务路由直接触发。
func (p *AdminAccountPlugin) createTemporaryAdmin(ctx context.Context) (temporaryAdminCredential, error) {
	if p.db == nil {
		return temporaryAdminCredential{}, fmt.Errorf("数据库未就绪")
	}

	// 生成 8 位随机账号 + 16 位随机密码（明文返回给运维一次，不存）
	newAccount, err := randomHex(4) // 8 位 hex
	if err != nil {
		return temporaryAdminCredential{}, fmt.Errorf("生成账号失败: %w", err)
	}
	plainPassword, err := randomHex(8) // 16 位 hex
	if err != nil {
		return temporaryAdminCredential{}, fmt.Errorf("生成密码失败: %w", err)
	}
	// 复用模块原生 hashPassword（sha256 hex），跟 verifyPassword 兼容
	passwordHash, err := hashPassword(plainPassword)
	if err != nil {
		return temporaryAdminCredential{}, fmt.Errorf("密码加密失败: %w", err)
	}

	expiresAt := time.Now().Add(temporaryAdminTTL)

	// 重置种子记录的字段，ID 永远不变。
	// 历史库里可能已经存在同 ID 记录但缺少超管/临时标记，所以每次生成都强制写回。
	// 如果种子缺失，则由该语句补回，避免平台入口返回一份无法登录的保底账号。
	// account 字段加随机后缀防 UNIQUE 冲突（旧值在表里，新值覆盖必须不冲突）
	_, err = p.db.ExecContext(ctx, `
		INSERT INTO account_accounts (id, account, password_hash, status, is_super_admin, is_temporary, expires_at)
		VALUES ($4, $1, $2, 'enabled', TRUE, TRUE, $3)
		ON CONFLICT (id) DO UPDATE
		   SET account = EXCLUDED.account,
		       password_hash = EXCLUDED.password_hash,
		       status = 'enabled',
		       is_super_admin = TRUE,
		       is_temporary = TRUE,
		       expires_at = EXCLUDED.expires_at,
		       updated_at = now()
	`, newAccount, passwordHash, expiresAt, temporarySuperAdminSeedID)
	if err != nil {
		return temporaryAdminCredential{}, fmt.Errorf("更新临时超管账号失败: %w", err)
	}

	return temporaryAdminCredential{
		Account:    newAccount,
		Password:   plainPassword,
		ExpiresAt:  expiresAt.UTC().Format(time.RFC3339),
		TTLSeconds: int(temporaryAdminTTL.Seconds()),
	}, nil
}

// startTemporaryAdminWorker 启动后台 worker，每分钟扫一次过期的临时超管账号
//
// 过期判定：is_temporary=true 且 status=enabled 且 expires_at < now()
// 处理：置 status=disabled，**不删记录、不改 account 字段**（保留下次按钮覆盖时复用）
//
// 调用方：Init() 里 go p.startTemporaryAdminWorker(ctx)
func (p *AdminAccountPlugin) startTemporaryAdminWorker(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	done := func() {}
	if p.registerWorker != nil {
		done = p.registerWorker()
	}
	defer done()

	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if p.db == nil {
				continue
			}
			_, err := p.db.ExecContext(ctx, `
				UPDATE account_accounts
				   SET status = 'disabled', updated_at = now()
				 WHERE is_temporary = TRUE
				   AND status = 'enabled'
				   AND expires_at IS NOT NULL
				   AND expires_at < now()
			`)
			if err != nil && p.logger != nil {
				p.logger.Warn("临时超管过期扫描失败", "err", err.Error())
			}
		}
	}
}

// randomHex 生成 n 字节的随机 hex 字符串（输出长度 2n）
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
