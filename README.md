# Qoder2api (Go)

![Go](https://img.shields.io/badge/Go-1.24-00ADD8?logo=go&logoColor=white) ![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey) ![Type](https://img.shields.io/badge/type-API%20Gateway-blue)

Qoder 转 OpenAI / Anthropic 兼容 API 的 Go 网关实现，支持页面登录。

## 构建 / 运行

```bash
go build -o qoder2api .
./qoder2api          # 默认子命令 serve，监听 127.0.0.1:8388
./qoder2api login    # 阻塞式 device flow 登录（凭据落盘 credentials.json）
./qoder2api claim    # 手动执行一次签到检查
```

## 接口

| 端点 | 说明 |
|---|---|
| `GET /health` | 健康检查 |
| `GET /v1/models` | 模型列表（仅限免档，附 price_factor / is_free / context_window） |
| `POST /v1/chat/completions`、`POST /v1/completions` | OpenAI 兼容（流式 + 工具调用） |
| `POST /v1/messages` | Anthropic Messages 兼容 |
| `POST /v1/responses` | OpenAI Responses 兼容 |
| `GET /login`、`GET /login/status` | device flow 登录（非阻塞）与状态轮询，授权链接打印在服务日志 |
| `GET /admin` | Web 管理面板（内置，开箱即用）：凭据状态、限免模型、device flow 登录。状态目录放一份自定义 `panel.html` 可覆盖内置版 |
| `GET /admin/api/overview` | 面板概览 JSON：`{credential:{valid,email,name,uid,token_type,expire_text}, models, local_auth}` |

## 配置（环境变量 > `.env` > 默认值）

| 变量 | 默认 | 说明 |
|---|---|---|
| `API_KEY` | 空 | 非空 = 入口鉴权（Bearer）。`/admin` 页面本身不鉴权，面板数据接口同样要求 key |
| `HOST` / `PORT` | `127.0.0.1` / `8388` | 监听地址（Docker 部署设 `HOST=0.0.0.0`） |
| `QODER2API_STATE_DIR` | exe 所在目录 | credentials.json / request.log / dumps/ / panel.html 落点 |
| `QODER_TIMEOUT` | `120` | 上游响应头超时（秒） |
| `QODER_PERSIST` | 开 | 设 `0` 时凭证仅内存态，不落盘（已存在的 credentials.json 照常读取） |
| `QODER_OPENAPI_HOST` / `QODER_GATEWAY_HOST` / `QODER_WEB_HOST` | 内置值 | 上游地址覆盖（联调时指向本地假上游，全程离线） |
| `DUMP` / `DUMP_DIR` / `DUMP_MAX_FILES` | 开 / `dumps` / `200` | 上游请求 / 响应落盘（排障用） |

## 凭据

单账号：`./qoder2api login` 或面板「重新登录」走 PKCE device flow，凭据落盘
`<状态目录>/credentials.json`——把 exe 放进原 Qoder2api 目录（或设
`QODER2API_STATE_DIR`）即可无缝接管 Python 版的凭据。双 token 族自动续期
（job ← jrt- 短期、device ← drt- 长效）；每日签到线程按服务端轮次窗口自动领取积分。

## Docker 部署

```bash
# 配置环境变量后启动
cp .env.example .env   # 按需填写
docker compose up -d
```

镜像同时发布到 GHCR：`ghcr.io/hj01857655/qoder2api`（跟随 v* 标签发布，含 latest，linux/amd64 + linux/arm64）。

二进制发版：推送 `v*` 标签后 Actions 自动构建 linux / windows / darwin 的 amd64 + arm64 六平台产物（tar.gz）并发布 Release。
