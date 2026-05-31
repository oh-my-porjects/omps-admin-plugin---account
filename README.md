# 账号管理 (account)

## 功能
提供后台账号登录、会话、账号管理、角色权限联动校验和临时超级管理员恢复能力。

## 接口

| 方法 | 路径 | 说明 | 鉴权 |
|--------|------|-------------|------|
| POST | /api/account/login | 后台账号密码登录并创建 Redis 会话 | public |
| GET | /api/account/me | 按会话令牌查询当前后台账号、角色状态和权限码 | public |
| POST | /api/account/_validate-password | 校验后台账号密码并返回基础身份信息 | public |
| POST | /api/account/create | 创建后台账号并绑定角色 | public |
| GET | /api/account/list | 分页查询后台账号 | public |
| GET | /api/account/detail | 查询后台账号详情和角色状态 | public |
| PUT | /api/account/update | 更新账号状态并覆盖角色绑定 | public |
| PUT | /api/account/reset-password | 重置后台账号密码 | public |
| POST | /api/admin/account/delete | 删除后台账号 | api_key |
| POST | /api/account/check-permission | 检查会话是否拥有指定权限码 | public |
| POST | /api/account/_create-temporary-admin | 生成临时超级管理员账号 | api_key |
| GET | /api/account/hello | 返回模块名称和版本 | public |
| POST | /api/account/admin/ping | 管理后台探活 | public |
| POST | /_internal/method-call/admin_account | Runtime 内部方法调用入口 | api_key |
| POST | /_internal/scheduled-trigger/admin_account | Runtime 内部手动触发定时任务 | api_key |
| POST | /_internal/selftest/admin_account | Runtime 内部自测入口 | api_key |

## 数据库

- `account_accounts` — 存储后台账号、密码哈希、启停状态、超级管理员标记和临时账号过期时间；`id` 主键，`account` 唯一，`status` 默认 `enabled`。
- `account_role_bindings` — 存储账号与角色的绑定关系；`id` 主键，`account_id` 外键级联删除，`account_id + role_id` 唯一。

## 设计说明

- 登录会话写入 Redis 而不是数据库，便于按 TTL 自动过期；Redis 不可用时登录会失败。
- 账号管理接口通过 `operator_session_token` 或管理端注入的后台会话识别操作者，并要求超级管理员或 `admin_account.manage` 权限。
- 角色有效性和权限码依赖 role 模块实时查询；角色缺失、禁用或删除会阻止登录、绑定或授权通过。
- 临时超级管理员复用固定种子账号，重复生成只覆盖同一行，10 分钟后后台 worker 自动禁用。
- 当前实现对外仍返回 `enabled/disabled` 状态文本和 RFC3339 时间字符串，尚未迁移为数字状态和 Unix 时间戳。

## 环境变量

- `ACCOUNT_SESSION_TTL_SECONDS` — 后台账号登录会话有效期秒数，默认值 `28800`
- `ADMIN_API_KEY` — 调用 role 管理接口和内部临时超管接口的管理密钥，平台注入
- `RUNTIME_ADDR` — Runtime HTTP 地址，未配置时按请求 Host 或 `127.0.0.1:8080` 兜底
- `REDIS_HOST_LAN` / `REDIS_HOST_WG` / `REDIS_PORT` / `REDIS_PASSWORD` / `REDIS_DB` — Redis 会话存储连接配置，端口默认 `6379`，DB 默认 `0`

## 依赖模块

- `role` — 调用 `GET /api/role/detail` 查询角色状态和权限点，调用 `POST /api/role/check-permission` 校验角色权限。

## 被依赖模块

- 无
