# 账号公共模块

- 项目后台只维护 `admin-intents.yaml`，它只能引用 `api-docs/` 已验证的 capability、字段和受控业务动作。
- 不得新增 `admin-web.yaml`、`AdminWebHint`、动态组件树、浏览器请求拼接或 V1–V3 页面协议。
- 修改后台接口、接口字段或操作规则时，必须同步更新 `api-docs/`、`admin-intents.yaml`、测试与本文档。
- `operator_session_token` 是 runtime 从已认证后台会话注入的可信参数，不得出现在浏览器表单或页面配置中。
