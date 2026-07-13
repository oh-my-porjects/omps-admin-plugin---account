package main

// 模块内部方法调用入口（POST /_internal/method-call/admin_account）
//
// 由 admin-server 透过 runtime 透传过来。请求体格式：
//
//	{ "method": "GetUserByID", "args": { "user_id": "123" } }
//
// 响应格式：
//
//	{ "code": 0, "data": <method 返回值>, "msg": "" }
//	{ "code": 1, "msg": "method not found / args invalid / ..." }
//
// 模块开发者：在 init() 里把方法注册到 Methods 表（key=方法名 → MethodFunc）

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// MethodFunc 方法签名：入参为请求上下文和 JSON 解码后的参数，返回值会被 JSON 序列化。
type MethodFunc func(ctx context.Context, args map[string]any) (any, error)

// Methods 全局方法表，模块开发者在 init 时注册
var Methods = map[string]MethodFunc{}

func init() {
	Routes["POST /_internal/method-call/admin_account"] = handleMethodCallInternal
	Methods["AdminAccountSelftestEcho"] = func(_ context.Context, args map[string]any) (any, error) {
		return map[string]any{
			"module": "admin_account",
			"echo":   args,
		}, nil
	}
	Methods["CreateTemporaryAdmin"] = func(ctx context.Context, args map[string]any) (any, error) {
		if len(args) != 0 {
			return nil, errors.New("CreateTemporaryAdmin 不接受参数")
		}
		return Plugin.createTemporaryAdmin(ctx)
	}
}

func handleMethodCallInternal(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Internal-Authenticated") != "true" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	defer func() {
		if rec := recover(); rec != nil {
			writeJSON(w, 1, nil, fmt.Sprintf("method call panic: %v", rec))
		}
	}()

	var req struct {
		Method string         `json:"method"`
		Args   map[string]any `json:"args"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 1, nil, "请求体解析失败: "+err.Error())
		return
	}
	if req.Method == "" {
		writeJSON(w, 1, nil, "method 不能为空")
		return
	}
	fn, ok := Methods[req.Method]
	if !ok {
		writeJSON(w, 1, nil, "未注册的方法: "+req.Method)
		return
	}
	result, err := fn(r.Context(), req.Args)
	if err != nil {
		writeJSON(w, 1, nil, err.Error())
		return
	}
	writeJSON(w, 0, result, "")
}
