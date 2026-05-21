package main

// selftest.go — 模块自测端点（POST /_internal/selftest）
//
// 由 admin-server 在部署完成后调用，模块自己读 tests/ 下的 JSON 用例文件
// 一个个执行（用 httptest 模拟请求直接调 handler，不走真实 HTTP），返回
// 通过/失败统计 + 每个 case 的请求/响应/期望对比。
//
// 安全：
//   - 只有 X-Internal-Token 匹配 RUNTIME_INTERNAL_TOKEN 时才执行
//   - panic 兜底：任何 case panic 算单个失败，不影响其它 case
//   - 一次只跑一组测试（sync.Mutex 全局锁）避免并发
//
// 用例格式见 tests/README.md

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed all:tests
var embeddedTests embed.FS

// 全局锁：避免并发自测互相污染数据
var selftestMu sync.Mutex

// init 注册自测端点到全局 Routes
//
// path 用 `/_internal/selftest/admin_account` 把模块名嵌进路径，避免
// 多模块部署在同一个 runtime 时 ServeMux 注册同 path 冲突。模板部署时
// admin_account 会被替换成实际模块 slug。
//
// 不在 main.go Routes var 里直接列，是因为 selftest 的 lookupRouteHandler
// 反向引用 Routes，会形成 var 初始化循环依赖。init 阶段 Routes 已构建好，
// 在这里追加自测端点不会触发循环检测。
//
// admin-server 调 runtime management 的 /internal/plugins/<name>/selftest
// 时，runtime 内部把 path 重写成 /_internal/selftest/<name> 给 plugin mux
// 处理，刚好命中这个 handler
func init() {
	Routes["POST /_internal/selftest/admin_account"] = handleSelftestInternal
}

// SelftestCase 单个用例
//
// 新版格式扩展（kind / actor / depends_on / side_effect_tables）：
//   - kind 默认 http；websocket / sse / file_upload 走 admin-web 测试页执行（selftest 跳过）
//   - actor 声明用什么身份调用：anonymous / user / admin / banned_user
//     selftest 内不强制注入鉴权（只测业务逻辑）；admin-web 跑用例时按 actor 注入
//   - depends_on：用例依赖关系，admin-web 一键全跑时按拓扑排序
//   - side_effect_tables：用例预期影响的表（admin-web 副作用对比时参考用，selftest 不消费）
type SelftestCase struct {
	Name             string            `json:"name"`
	Kind             string            `json:"kind,omitempty"`
	Actor            string            `json:"actor,omitempty"`
	DependsOn        []string          `json:"depends_on,omitempty"`
	Method           string            `json:"method,omitempty"`
	Path             string            `json:"path,omitempty"`
	Headers          map[string]string `json:"headers,omitempty"`
	Body             json.RawMessage   `json:"body,omitempty"`
	ExpectStatus     *int              `json:"expect_status,omitempty"`   // HTTP 状态码（可选）
	ExpectField      map[string]any    `json:"expect_field,omitempty"`    // JSON 字段路径 → 期望值，如 "status": 0
	ExpectContains   string            `json:"expect_contains,omitempty"` // 响应体包含某子串
	SideEffectTables []string          `json:"side_effect_tables,omitempty"`
	// WS / SSE / 文件上传专用字段（selftest 仅识别 kind 跳过，由 admin-web 测试页执行）
	WSSteps  []map[string]any `json:"ws_steps,omitempty"`
	SSESteps []map[string]any `json:"sse_steps,omitempty"`
	Upload   map[string]any   `json:"upload,omitempty"`
}

// SelftestFile 一个 .test.json 文件
type SelftestFile struct {
	API   string         `json:"api"` // 例如 "POST /api/user/register"
	Cases []SelftestCase `json:"cases"`
}

func handleSelftestInternal(w http.ResponseWriter, r *http.Request) {
	// 内部 token 验证
	expect := os.Getenv("RUNTIME_INTERNAL_TOKEN")
	if expect == "" || r.Header.Get("X-Internal-Token") != expect {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	defer func() {
		if rec := recover(); rec != nil {
			writeJSON(w, 1, nil, fmt.Sprintf("selftest panic: %v", rec))
		}
	}()

	selftestMu.Lock()
	defer selftestMu.Unlock()

	results := runAllSelftests()
	writeJSON(w, 0, results, "")
}

func runAllSelftests() map[string]any {
	files, err := embeddedTests.ReadDir("tests")
	if err != nil {
		return map[string]any{"total": 0, "passed": 0, "failed": 0, "results": []any{}, "error": "tests 目录读取失败: " + err.Error()}
	}

	var results []map[string]any
	passed, failed := 0, 0

	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".test.json") {
			continue
		}
		raw, err := embeddedTests.ReadFile("tests/" + f.Name())
		if err != nil {
			results = append(results, map[string]any{
				"file":   f.Name(),
				"passed": false,
				"error":  "读取失败: " + err.Error(),
			})
			failed++
			continue
		}
		var sf SelftestFile
		if err := json.Unmarshal(raw, &sf); err != nil {
			results = append(results, map[string]any{
				"file":   f.Name(),
				"passed": false,
				"error":  "JSON 解析失败: " + err.Error(),
			})
			failed++
			continue
		}
		for i, c := range sf.Cases {
			r := runSingleCase(sf.API, f.Name(), i, c)
			results = append(results, r)
			if p, _ := r["passed"].(bool); p {
				passed++
			} else {
				failed++
			}
		}
	}

	return map[string]any{
		"total":   passed + failed,
		"passed":  passed,
		"failed":  failed,
		"results": results,
	}
}

func runSingleCase(api, file string, idx int, c SelftestCase) map[string]any {
	// 非 HTTP 用例（WS / SSE / 文件上传）由 admin-web 测试页执行，selftest 跳过
	kind := strings.ToLower(c.Kind)
	if kind == "websocket" || kind == "sse" || kind == "file_upload" {
		return map[string]any{
			"file":           file,
			"index":          idx,
			"name":           c.Name,
			"api":            api,
			"kind":           kind,
			"passed":         true,
			"skipped_reason": "kind=" + kind + " 仅在 admin-web 测试页执行",
		}
	}

	method := strings.ToUpper(c.Method)
	path := c.Path
	if method == "" || path == "" {
		// 从 SelftestFile.api 拆 "POST /api/x"
		parts := strings.SplitN(api, " ", 2)
		if len(parts) == 2 {
			if method == "" {
				method = strings.ToUpper(parts[0])
			}
			if path == "" {
				path = parts[1]
			}
		}
	}

	// 模板变量替换：path/headers/body 都跑一遍，让用例可以写 ${ts}/${rand} 等占位
	// 同一 case 内多次出现的同名占位会拿到相同值（保证 body 里手机号和 expect_field 里手机号一致）
	tmplVars := buildTemplateVars()
	path = applyTemplateVars(path, tmplVars)

	result := map[string]any{
		"file":   file,
		"index":  idx,
		"name":   c.Name,
		"api":    api,
		"method": method,
		"path":   path,
	}

	handler := lookupRouteHandler(method, path)
	if handler == nil {
		result["passed"] = false
		result["error"] = fmt.Sprintf("未找到匹配的路由 handler: %s %s（检查 Routes 表）", method, path)
		return result
	}

	bodyBytes := []byte(applyTemplateVars(string(c.Body), tmplVars))
	var bodyReader = bytes.NewReader(nil)
	if len(bodyBytes) > 0 {
		bodyReader = bytes.NewReader(bodyBytes)
	}
	req := httptest.NewRequest(method, path, bodyReader)
	for k, v := range c.Headers {
		req.Header.Set(k, applyTemplateVars(v, tmplVars))
	}
	if len(bodyBytes) > 0 && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	result["request_body"] = string(bodyBytes)

	rr := httptest.NewRecorder()
	start := time.Now()
	func() {
		defer func() {
			if rec := recover(); rec != nil {
				rr.Code = 500
				rr.Body.Reset()
				rr.Body.WriteString(fmt.Sprintf("handler panic: %v", rec))
			}
		}()
		handler(rr, req)
	}()
	result["elapsed_ms"] = time.Since(start).Milliseconds()
	result["http_code"] = rr.Code

	respBytes := rr.Body.Bytes()
	respStr := string(respBytes)
	if len(respStr) > 4096 {
		respStr = respStr[:4096] + "...(truncated)"
	}
	result["response_body"] = respStr

	// 期望比对
	if c.ExpectStatus != nil && rr.Code != *c.ExpectStatus {
		result["passed"] = false
		result["fail_reason"] = fmt.Sprintf("HTTP code 期望 %d 实际 %d", *c.ExpectStatus, rr.Code)
		return result
	}
	expectContains := applyTemplateVars(c.ExpectContains, tmplVars)
	if expectContains != "" && !strings.Contains(string(respBytes), expectContains) {
		result["passed"] = false
		result["fail_reason"] = fmt.Sprintf("响应不含期望子串: %q", expectContains)
		return result
	}
	if len(c.ExpectField) > 0 {
		var obj map[string]any
		if err := json.Unmarshal(respBytes, &obj); err != nil {
			result["passed"] = false
			result["fail_reason"] = "响应不是合法 JSON，无法对比字段"
			return result
		}
		for key, expect := range c.ExpectField {
			expectResolved := resolveTemplateAny(expect, tmplVars)
			actual := jsonGet(obj, key)
			if !valuesEqual(expectResolved, actual) {
				result["passed"] = false
				result["fail_reason"] = fmt.Sprintf("字段 %s 期望 %v 实际 %v", key, expectResolved, actual)
				return result
			}
		}
	}

	result["passed"] = true
	return result
}

// lookupRouteHandler 在全局 Routes 表找匹配的 handler
// 支持 "METHOD /path" 和裸 "/path" 两种 key 格式
func lookupRouteHandler(method, path string) http.HandlerFunc {
	if h, ok := Routes[method+" "+path]; ok {
		return h
	}
	if h, ok := Routes[path]; ok {
		return h
	}
	if q := strings.IndexByte(path, '?'); q >= 0 {
		return lookupRouteHandler(method, path[:q])
	}
	// 尝试 "GET /api/.../{id}" 这种 pattern：不严格匹配，只兜底
	for key, h := range Routes {
		k := key
		// 忽略 pattern 里 {x} 占位的差异
		k = stripPathPlaceholders(k)
		p := stripPathPlaceholders(method + " " + path)
		if k == p {
			return h
		}
	}
	return nil
}

func stripPathPlaceholders(s string) string {
	out := strings.Builder{}
	depth := 0
	for _, r := range s {
		if r == '{' {
			depth++
			continue
		}
		if r == '}' {
			depth--
			continue
		}
		if depth == 0 {
			out.WriteRune(r)
		}
	}
	return out.String()
}

// jsonGet 按 "a.b.c" 路径取嵌套 JSON 字段
func jsonGet(obj any, path string) any {
	cur := obj
	for _, p := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[p]
	}
	return cur
}

// valuesEqual 类型不严格的相等比较（JSON 数字都是 float64，跟用户写的 int 兼容）
func valuesEqual(a, b any) bool {
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

// templateVars 单 case 内的模板变量上下文：同名占位多次出现保证拿到同一个值
//   ${ts}        当前秒级时间戳（10 位）
//   ${ts_ms}     当前毫秒时间戳（13 位）
//   ${rand}      默认 6 位 hex 随机串
//   ${rand:N}    N 位 hex 随机串（N=2~32）
//   ${uuid}      32 位 hex（不带横线）
//
// 用例场景：注册接口要避免手机号/邮箱重复 → body 里写 "phone": "138${rand}"，
// expect_field 里同步写 "data.phone": "138${rand}"，两次替换得到相同值，断言才能过。
type templateVars struct {
	ts       string
	tsMs     string
	uuid     string
	rangeTag string
	cache    map[string]string // 缓存 ${rand:N} 等动态生成的占位
}

func buildTemplateVars() *templateVars {
	now := time.Now()
	return &templateVars{
		ts:       strconv.FormatInt(now.Unix(), 10),
		tsMs:     strconv.FormatInt(now.UnixMilli(), 10),
		uuid:     randHex(32),
		rangeTag: "test_req_selftest_",
		cache:    map[string]string{},
	}
}

// 占位匹配：${name} 或 ${name:arg}
var templateVarRE = regexp.MustCompile(`\$\{([a-zA-Z_]+)(?::([a-zA-Z0-9_-]+))?\}`)

func applyTemplateVars(s string, v *templateVars) string {
	if s == "" || v == nil {
		return s
	}
	return templateVarRE.ReplaceAllStringFunc(s, func(match string) string {
		groups := templateVarRE.FindStringSubmatch(match)
		name, arg := groups[1], groups[2]
		key := name
		if arg != "" {
			key = name + ":" + arg
		}
		if cached, ok := v.cache[key]; ok {
			return cached
		}
		val := resolveTemplateName(name, arg, v)
		v.cache[key] = val
		return val
	})
}

func resolveTemplateName(name, arg string, v *templateVars) string {
	switch name {
	case "internal_token":
		return os.Getenv("RUNTIME_INTERNAL_TOKEN")
	case "range_tag":
		return v.rangeTag
	case "admin_session_token":
		return selftestSessionToken("10000000-0000-0000-0000-000000000001")
	case "operator_session_token":
		return selftestSessionToken("10000000-0000-0000-0000-000000000002")
	case "role_state_session_token":
		return selftestSessionToken("10000000-0000-0000-0000-000000000004")
	case "ts":
		return v.ts
	case "ts_ms":
		return v.tsMs
	case "uuid":
		return v.uuid
	case "rand":
		n := 6
		if arg != "" {
			if k, err := strconv.Atoi(arg); err == nil && k > 0 && k <= 32 {
				n = k
			}
		}
		return randHex(n)
	}
	// 未知占位原样保留，方便用户发现拼错
	if arg == "" {
		return "${" + name + "}"
	}
	return "${" + name + ":" + arg + "}"
}

// randHex 返回 n 位小写 hex 字符串
func randHex(n int) string {
	bytesNeeded := (n + 1) / 2
	buf := make([]byte, bytesNeeded)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand 失败极罕见，退化用时间戳保证唯一性
		fallback := strconv.FormatInt(time.Now().UnixNano(), 16)
		if len(fallback) >= n {
			return fallback[:n]
		}
		return fallback
	}
	return hex.EncodeToString(buf)[:n]
}

func selftestSessionToken(accountID string) string {
	if Plugin == nil {
		return ""
	}
	token, _, err := Plugin.createSession(context.Background(), accountID)
	if err != nil {
		return ""
	}
	return token
}

// resolveTemplateAny 对 expect_field 的 value 做模板替换；非字符串原样返回
func resolveTemplateAny(v any, vars *templateVars) any {
	if s, ok := v.(string); ok {
		return applyTemplateVars(s, vars)
	}
	return v
}
