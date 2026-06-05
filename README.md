# 账号管理 (account)

## 功能
提供后台账号、密码登录、Redis 会话、账号管理权限校验和临时超级管理员账号能力。

## 接口

| 方法 | 路径 | 说明 | 鉴权 |
|--------|------|-------------|------|
| POST | /api/account/login | 后台账号密码登录并创建会话 | public |
| GET | /api/account/me | 按会话查询当前后台账号、角色状态和权限码 | public |
| POST | /api/account/_validate-password | 校验后台账号密码并返回基础身份 | public |
| POST | /api/account/create | 创建后台账号并绑定一个有效角色 | public |
| GET | /api/account/list | 分页查询后台账号列表 | public |
| GET | /api/account/detail | 查询后台账号详情和角色状态 | public |
| PUT | /api/account/update | 更新账号状态并覆盖角色绑定 | public |
| PUT | /api/account/reset-password | 重置后台账号密码 | public |
| POST | /api/admin/account/delete | 删除后台账号及角色绑定 | api_key |
| POST | /api/account/check-permission | 校验会话是否拥有指定权限码 | public |
| POST | /api/account/_create-temporary-admin | 内部生成 10 分钟有效临时超级管理员 | api_key |
| GET | /api/account/hello | 返回模块名称和版本 | public |
| POST | /api/account/admin/ping | 管理端探活 | api_key |
| POST | /_internal/method-call/admin_account | Runtime 内部方法调用 | api_key |
| POST | /_internal/scheduled-trigger/admin_account | Runtime 内部触发定时任务 | api_key |
| POST | /_internal/selftest/admin_account | Runtime 内部执行模块自测 | api_key |

## 数据库

- `account_accounts` — 存储后台账号；关键字段包括 `id` 主键、唯一 `account`、`password_hash`、`status`、`is_super_admin`、`is_temporary`、`expires_at`、`created_at`、`updated_at`。
- `account_role_bindings` — 存储账号到角色的绑定；关键字段包括 `id` 主键、`account_id` 外键级联删除、`role_id`，并通过唯一约束限制同一账号同一角色不重复，迁移条件满足时追加单账号单角色唯一索引。

## 设计说明
- 后台登录会话写入 Redis 并依赖 TTL 自动过期，数据库只保存账号和角色绑定，避免会话状态长期落库。
- 账号管理操作优先使用请求体中的 `operator_session_token`，为空时可从管理端请求头兜底；权限要求是超级管理员或命中 `admin_account.manage`。
- 当前实现强制每个普通账号只保留一个有效角色，创建和更新前会调用 role 模块确认角色存在且启用。
- 临时超级管理员复用固定种子账号，只覆盖账号名、密码哈希、状态和过期时间；过期后 worker 禁用记录而不删除。
- 状态和时间对外仍按旧实现返回字符串，例如 `enabled`、`disabled` 和 RFC3339 时间；文档需如实标注该边界。

## 环境变量
- `ACCOUNT_SESSION_TTL_SECONDS` — 后台账号登录会话有效期秒数，默认值 `28800`。
- `ADMIN_API_KEY` — 调用 role 模块和部分内部接口鉴权使用的平台管理密钥，默认值无。
- `RUNTIME_ADDR` — 调用 role 模块时使用的 Runtime 地址，默认从请求 Host 推断，兜底 `127.0.0.1:8080`。
- `REDIS_HOST_LAN` / `REDIS_HOST_WG` / `REDIS_PORT` / `REDIS_PASSWORD` / `REDIS_DB` — Redis 会话存储连接配置，端口默认 `6379`，库默认 `0`。

## 依赖模块
- `role` — 调用 `GET /api/role/detail` 获取角色状态和权限点，调用 `POST /api/role/check-permission` 校验角色权限码。

## 被依赖模块
- 无
