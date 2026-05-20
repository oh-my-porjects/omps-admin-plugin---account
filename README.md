# 后台账号模块 (account)

## Features
负责后台账号登录、会话校验、账号管理、角色权限聚合、临时超级管理员账号和内部运维触发入口。

## Endpoints

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| POST | /api/account/login | 后台账号密码登录并创建 Redis 会话 | public |
| GET | /api/account/me | 按 session_token 查询当前账号和权限 | public |
| POST | /api/account/create | 创建后台账号并绑定角色 | public |
| GET | /api/account/list | 分页查询后台账号 | public |
| GET | /api/account/detail | 查询后台账号详情 | public |
| PUT | /api/account/update | 更新账号状态和角色绑定 | public |
| PUT | /api/account/reset-password | 重置后台账号密码 | public |
| POST | /api/account/check-permission | 校验会话是否拥有指定权限码 | public |
| POST | /api/account/_create-temporary-admin | 生成一次性临时超级管理员账号 | api_key |
| GET | /api/account/hello | 返回模块名和版本 | public |
| POST | /{admin_prefix}/api/account/admin/ping | 管理后台连通性检查 | api_key |
| POST | /_internal/method-call/admin_account | Runtime 内部方法调用入口 | api_key |
| POST | /_internal/scheduled-trigger/admin_account | Runtime 内部定时任务触发入口 | api_key |

## Database

- `account_accounts` — 存储后台账号，关键字段包括 `id` 主键、唯一 `account`、`password_hash`、`status`、`is_super_admin`、`is_temporary`、`expires_at`、`created_at`、`updated_at`。
- `account_role_bindings` — 存储账号与角色绑定，关键字段包括 `account_id` 外键级联删除、`role_id`，并通过 `UNIQUE(account_id, role_id)` 防重复绑定。

## Design Notes

- 登录会话写入 Redis 而不是账号表，便于 TTL 自动过期；Redis 不可用时登录会失败。
- 管理账号的权限不依赖 HTTP 登录中间件，而是显式传入 `operator_session_token` 并校验 `admin_account.manage`，适配后台管理前端的会话模型。
- 角色详情和权限判断由 role 模块提供，本模块只保存角色 ID 绑定；role 模块不可用时账号创建、详情、权限聚合会失败或显示缺失状态。
- 临时超级管理员复用固定种子账号，避免重复创建高权限账号；10 分钟后后台 worker 自动禁用但不删除记录。
- 密码当前使用 SHA-256 哈希，代码未实现盐或慢哈希，安全强度依赖部署侧访问控制。

## Environment Variables

- `ADMIN_ACCOUNTS_SESSION_TTL_SECONDS` — 后台账号会话有效期秒数，默认 `28800`。
- `ADMIN_API_KEY` — 调用 role 模块和临时超管内部接口的 API Key，默认空。
- `RUNTIME_ADDR` — Runtime 地址，用于回调 role 模块接口，默认从请求 Host 推导，兜底 `127.0.0.1:8080`。
- `REDIS_HOST_LAN` / `REDIS_HOST_WG` — Redis 地址来源，默认空；为空时无法创建登录会话。
- `REDIS_PORT` — Redis 端口，默认 `6379`。
- `REDIS_PASSWORD` — Redis 密码，默认空。
- `REDIS_DB` — Redis DB 编号，默认 `0`。
- `RUNTIME_INTERNAL_TOKEN` — 内部方法调用和定时任务触发鉴权 token，默认空。

## Dependencies

- `role` — 调用 `GET /api/admin-role/detail` 查询角色状态和权限，调用 `POST /api/admin-role/check-permission` 校验角色权限。

## Dependents

- Runtime / admin-server — 调用内部方法、定时任务、自测和临时超级管理员生成接口。
