# Sub2API Account Guardian

Sub2API Account Guardian 是一个给 [Sub2API](https://github.com/) 使用的外置 Docker 伴生服务。它不修改 Sub2API 源码，通过数据库监听和只读/写必要账号状态的方式，帮助 Sub2API 更稳定地使用 OpenAI OAuth 账号池。

## 为什么做这个项目

Sub2API 在使用 OpenAI OAuth 账号池时，常见问题是：某个账号已经出现认证错误，但它仍可能继续参与调度，导致请求失败、接口不稳定，甚至一个坏账号反复影响业务。

这个项目的目标是：

- 当 Sub2API 发现账号内部认证错误时，第一时间关闭该账号调度。
- 自动尝试刷新 token，能复活就恢复账号。
- 用 `gpt-5.4-mini` 做最终测活确认。
- 对确认死亡的账号执行数据库软删除。
- 对网络、TLS、超时、5xx、429、额度限制等非账号死亡问题保持保守，不误删。
- 提供一个中文 Web 面板查看账号数量、处理日志、手动检测软删除账号是否可恢复。

一句话：**让 Sub2API 的 OpenAI 账号池自动摘除坏号、复活可救账号，减少坏号影响 API 稳定性。**

## 它不是什么

- 不是全局扫号器。
- 不是批量注册工具。
- 不是 Sub2API 的源码 fork。
- 不会因为网络错误、429、额度限制就删除账号。
- 默认使用软删除，不直接物理删除账号。

## 工作模式

Guardian 有两种触发方式：

1. **Postgres 触发器唤醒**
   - 当 `accounts` 表里 OpenAI OAuth 账号出现认证类错误时，触发 `NOTIFY`。
   - Guardian 收到通知后立即处理对应账号。

2. **定时兜底扫描**
   - 默认每 30 秒扫描一次数据库里已标记为认证错误的账号。
   - 防止通知丢失。

处理流程：

```text
Sub2API 标记账号错误
        ↓
Guardian 收到事件/扫描到错误
        ↓
判断是否为账号内部认证错误
        ↓
先关闭调度 schedulable=false
        ↓
尝试刷新 refresh_token
        ↓
用 gpt-5.4-mini 调 Sub2API 测活
        ↓
可用：恢复 active + 打开调度
限流/额度：保留给 Sub2API 自己处理
需要重新登录：关闭调度，保留账号
确认认证死亡：软删除
网络/超时/5xx：不删除
```

## 错误处理策略

| 错误类型 | 行为 |
|---|---|
| `token_invalidated` / `token_revoked` / `token_expired` / `invalid_grant` / 401 认证错误 | 进入复活与测活流程 |
| `refresh_token_reused` | 当前保存的 RT 已废，通常保持软删除或等待人工重新登录 |
| `app_session_terminated` | 需要人工重新登录，关闭调度，不自动删除 |
| `account_deactivated` | OpenAI 官方停用账号，通常可长期保留软删除，后续可按需物理删除 |
| 429 / quota / rate limit | 不删除，交给 Sub2API 限流机制 |
| timeout / EOF / TLS / DNS / 5xx | 网络或上游问题，不删除 |
| 参数错误 / 模型不支持 | 不删除 |

## Web 面板

默认地址：

```text
http://127.0.0.1:8788
```

面板功能：

- 账号数量总览
- 最近账号状态
- 调度开关状态
- 错误分类
- 中文处理日志
- 手动保存配置
- 手动全量检测已软删除账号是否能恢复

软删除账号复活检测：

- 只处理 `deleted_at IS NOT NULL` 且有 `refresh_token` 的 OpenAI OAuth 账号。
- 默认并发 5。
- 能刷新并测活成功：恢复账号为正常状态。
- 失败或不确定：继续软删除。

## Docker Compose 安装

### 1. 准备 `.env`

复制示例文件：

```bash
cp .env.example .env
```

编辑 `.env`：

```env
SUB2API_URL=http://sub2api:8080
SUB2API_KEY=你的_Sub2API_Admin_Key

POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_DB=sub2api
POSTGRES_USER=sub2api
POSTGRES_PASSWORD=你的_Postgres_密码

TEST_MODEL=gpt-5.4-mini
OPENAI_GROUP_ID=2
WEB_PORT=8788
```

> 如果你的 Sub2API / Postgres 容器名称不同，需要改 `SUB2API_URL` 和 `POSTGRES_HOST`。

### 2. 安装数据库触发器

把 `sql/001_account_guardian_notify.sql` 导入 Sub2API 的 Postgres 数据库：

```bash
docker exec -i sub2api-postgres-dev psql -U sub2api -d sub2api < sql/001_account_guardian_notify.sql
```

如果你的数据库容器名不是 `sub2api-postgres-dev`，替换成你自己的容器名。

这个 SQL 可以重复执行。

### 3. 启动服务

本地源码构建：

```bash
docker compose up -d --build
```

查看日志：

```bash
docker logs -f sub2api-account-guardian
```

打开面板：

```text
http://127.0.0.1:8788
```

## 使用预构建镜像

如果你发布到了 GHCR，可以把 compose 里的 `build` 改成：

```yaml
image: ghcr.io/YOUR_GITHUB_USERNAME/sub2api-account-guardian:latest
```

然后运行：

```bash
docker compose up -d
```

## 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `SUB2API_URL` | `http://sub2api:8080` | Sub2API 服务地址 |
| `SUB2API_KEY` | 必填 | Sub2API Admin Key |
| `DATABASE_URL` | 空 | 可直接提供完整 Postgres URL |
| `POSTGRES_HOST` | `postgres` | Postgres 主机 |
| `POSTGRES_PORT` | `5432` | Postgres 端口 |
| `POSTGRES_DB` | `sub2api` | 数据库名 |
| `POSTGRES_USER` | `sub2api` | 数据库用户 |
| `POSTGRES_PASSWORD` | 空 | 数据库密码 |
| `TEST_MODEL` | `gpt-5.4-mini` | 测活模型 |
| `MONITOR_INTERVAL_SECONDS` | `30` | 定时扫描间隔 |
| `MONITOR_BATCH_SIZE` | `50` | 每轮扫描账号数 |
| `TEST_WORKERS` | `10` | 普通处理并发 |
| `REFRESH_WORKERS` | `5` | 预留刷新并发配置 |
| `RETRY_ATTEMPTS` | `10` | 网络/不确定错误重试次数 |
| `RETRY_DELAY_MS` | `500` | 重试间隔毫秒 |
| `OPENAI_GROUP_ID` | `2` | 恢复账号时绑定的 OpenAI 分组 ID |
| `DRY_RUN` | `0` | 演练模式，不实际修改 |
| `ONCE` | `0` | 只跑一轮后退出 |
| `WEB_ENABLED` | `1` | 是否开启 Web 面板 |
| `WEB_ADDR` | `:8788` | 面板监听地址 |
| `AUDIT_DIR` | `/app/data/sub2api_guardian` | 审计日志目录 |

## 审计日志

Guardian 会写 JSONL 审计日志：

```text
/app/data/sub2api_guardian/guardian-YYYYMMDD.jsonl
```

日志记录：

- 账号 ID / 名称
- 初始状态
- 错误分类
- 是否尝试刷新 token
- 测活结果
- 最终动作
- 最终原因

## 安全建议

- 第一次部署建议先设置 `DRY_RUN=1`，观察日志确认分类符合预期。
- 不要把 `.env`、真实 admin key、数据库密码提交到 GitHub。
- 生产环境不要把面板暴露到公网，建议只监听 `127.0.0.1` 或放在内网。
- 如果你不希望自动软删除，可以改代码策略为“只关闭调度，不软删除”。

## 开发

运行测试：

```bash
go test ./...
```

本地构建：

```bash
go build ./cmd/guardian
```

## License

MIT
