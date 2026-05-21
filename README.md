# 账号公共模块 (account)

## Features
提供后台账号、登录会话、账号管理权限校验和临时超级管理员账号能力。

## Endpoints

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| POST | /api/account/login | 后台账号密码登录并创建 Redis 会话 | public |
| GET | /api/account/me | 按会话令牌查询当前账号、角色状态和权限码 | public |
| POST | /api/account/create | 创建后台账号并绑定角色 | public |
| GET | /api/account/list | 分页查询后台账号 | public |
| GET | /api/account/detail | 查询后台账号详情和角色状态 | public |
| PUT | /api/account/update | 更新账号状态并覆盖角色绑定 | public |
| PUT | /api/account/reset-password | 重置后台账号密码 | public |
| POST | /api/account/check-permission | 校验会话是否拥有指定权限码 | public |
| POST | /api/account/_create-temporary-admin | 内部生成临时超级管理员账号 | api_key |
| GET | /api/account/hello | 返回模块名称和版本 | public |
| POST | /api/account/admin/ping | 管理后台探活 | api_key |
| POST | /_internal/method-call/admin_account | Runtime 内部方法调用入口 | api_key |
| POST | /_internal/scheduled-trigger/admin_account | Runtime 内部定时任务触发入口 | api_key |

## Database

- `account_accounts` — 存储后台账号；关键字段包括 `id` 主键、唯一 `account`、`password_hash`、`status`、`is_super_admin`、临时账号标记 `is_temporary` 和 `expires_at`。
- `account_role_bindings` — 存储账号与角色绑定；关键字段包括 `account_id` 外键、`role_id`，并通过 `(account_id, role_id)` 唯一约束防止重复绑定。

## Design Notes
- 会话令牌存入 Redis 而不是账号表，便于通过 TTL 自动过期；Redis 不可用时登录会失败。
- 账号管理接口使用 `operator_session_token` 和 `admin_account.manage` 权限点做业务鉴权，因此 HTTP 层仍按 public 路由暴露。
- 角色有效性和权限判断依赖 role 模块实时查询，避免账号模块复制角色权限状态，但会受 role 模块可用性影响。
- 临时超级管理员复用固定种子记录，10 分钟后由后台 worker 禁用，避免产生多条长期高权限账号。
- 密码当前使用 SHA-256 摘要存储，没有独立盐值或自适应哈希成本。

## Environment Variables
- `ACCOUNT_SESSION_TTL_SECONDS` — 后台账号登录会话有效期秒数，默认 `28800`。
- `ADMIN_API_KEY` — 内部临时超管接口鉴权 token，平台注入。
- `RUNTIME_INTERNAL_TOKEN` — 内部方法调用和定时任务触发鉴权 token，平台注入。
- `RUNTIME_ADDR` — 调用 role 模块接口时使用的 Runtime 地址，缺省时回退到请求 Host 或 `127.0.0.1:8080`。
- `REDIS_HOST_LAN` / `REDIS_HOST_WG` / `REDIS_PORT` / `REDIS_PASSWORD` / `REDIS_DB` — Redis 会话存储连接配置，端口默认 `6379`，DB 默认 `0`。

## Dependencies
- `role` — 调用 `GET /api/role/detail` 查询角色状态和权限，调用 `POST /api/role/check-permission` 校验角色权限点。

## Dependents
- `role` — 可向本模块约定的 `admin_account.manage` 权限点授权，供账号管理接口鉴权使用。
