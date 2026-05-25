package main

// ws_example.go — WebSocket 能力使用示范
//
// 平台已经在 runtime 层把 WebSocket 通道做好了，模块**不需要**自己升级连接、
// 解析帧、做心跳。模块只需要：
//
//   1. 把已有的 HTTP 接口照常写在 Routes 里——客户端用 ws 调时由平台翻译员转成 HTTP 请求
//      送到模块 handler，所以一个接口天然两栖（HTTP + WebSocket）
//
//   2. 想主动给某个用户发消息时，调 PluginContext.Push / Emit / Broadcast
//
//   3. 如果是登录模块：在专用 auth provider 实现里调 PluginContext.RegisterAuth
//      把鉴权回调交给 runtime（普通业务模块不要调用）
//
// 客户端协议：见 docs/ws-协议规范.md（项目根 docs 目录）

import (
	"context"
	"net/http"
	"time"
)

// ============================================================================
// 示例 1：业务模块主动推送
// ============================================================================
//
// 场景：用户 A 给用户 B 发了一条好友请求，业务模块在保存请求记录后
// 想立即通知用户 B（如果在线）。
//
// 调用 Plugin.ctxPush 即可——必送达进入 ws_outbox 表，离线用户上线后补发。

func (p *AdminAccountPlugin) sendFriendRequest(ctx context.Context, fromUserID, toUserID, note string) error {
	// 1. 写库（业务自己做）
	// _, err := p.db.ExecContext(ctx, "INSERT INTO friend_requests ...")

	// 2. 通知对方（必送达）
	if p.push != nil {
		_, _ = p.push(ctx, toUserID, "friend.request_received", map[string]any{
			"from_user_id": fromUserID,
			"note":         note,
			"created_at":   time.Now().UTC().Format(time.RFC3339),
		})
	}
	return nil
}

// ============================================================================
// 示例 2：尽力而为推送（聊天打字中等实时性强、丢失无所谓的场景）
// ============================================================================

func (p *AdminAccountPlugin) handleTypingNotice(w http.ResponseWriter, r *http.Request) {
	fromUserID := getUserID(r)
	toUserID := r.URL.Query().Get("to")
	if fromUserID == "" || toUserID == "" {
		writeJSON(w, -1, nil, "missing user id")
		return
	}
	if p.emit != nil {
		p.emit(toUserID, "chat.typing", map[string]any{
			"from_user_id": fromUserID,
		})
	}
	writeJSON(w, 0, nil, "ok")
}

// ============================================================================
// 登录模块注册鉴权回调必须放在认证模块自己的实现里，不要从普通模块模板复制。
// 认证模块还必须在 plugin.yaml 声明 capabilities.auth_provider。

// ============================================================================
// 把推送 API 缓存到 plugin 实例字段，方便业务函数取用
// ============================================================================
//
// 在你的 AdminAccountPlugin struct 里加这些字段，并在 Init 里赋值：
//
//   type AdminAccountPlugin struct {
//       // ...原有字段
//       push      func(ctx context.Context, userID, code string, data any) (int64, error)
//       emit      func(userID, code string, data any) bool
//       broadcast func(ctx context.Context, userIDs []string, code string, data any) ([]int64, error)
//       isOnline  func(userID string) bool
//   }
//
//   func (p *AdminAccountPlugin) Init(ctx PluginContext) error {
//       // ...原有初始化
//       p.push = ctx.Push
//       p.emit = ctx.Emit
//       p.broadcast = ctx.Broadcast
//       p.isOnline = ctx.IsOnline
//       return nil
//   }
//
// 模板 main.go 里现在的 Init 已经做了 db / logger / lifecycleCtx / registerWorker
// 的赋值，接入 ws 推送只是再多几行复制
