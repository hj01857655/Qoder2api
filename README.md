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

### 协议适配（实测，模型 `DeepSeek-Flash`）

| 能力 | chat/completions | responses | messages |
|---|:---:|:---:|:---:|
| 非流式 | ✅ | ✅ | ✅ |
| 流式 | ✅ | ✅ | ✅ |
| 工具调用 | ✅ | ✅ | ✅ |
| 图片输入 | ✅ | ✅ | ✅ |
| 思考内容 | ✅ | ✅ | ✅ |

流式事件序列与字段映射经上游实测核对；能力判定以单次请求（排队窗口内）返回 200 为准。

## 排队与重试

`10605 / RESOURCE_LIMIT` 是**模型级容量信号**（`queueType:p3`、`serviceAvailable:false`），
不是封号、也不是账号问题：同一模型的所有账号共享一个池，换号不解除排队，换模型或错峰才行。

| 变量 | 默认 | 说明 |
|---|---|---|
| `QODER_QUEUE_WAIT_MODE` | `visible` | `visible` 等队列放行后重试；`fast` 立即返回 `503` + `Retry-After`/`retry_after`（实测 0.5s 返回）；`wait` 静默 sleep（旧行为） |
| `QODER_QUEUE_MAX_ROUNDS` | `5` | 最多排队重试轮次 |
| `QODER_QUEUE_WAIT_MAX_SECS` | `180` | 单轮等待上限（秒） |
| `QODER_QUEUE_WAIT_BUDGET_SECS` | `300` | 整次请求总等待预算（秒） |
| `QODER_CONNECT_RETRY_MAX_ELAPSED` | `150` | 连接类错误重试的耗时上限（秒） |

排队等待期间每 5 秒检查客户端是否断开，断开即中止，不占住 worker。

## 免费模型

`/v1/models` 只列限免档：`Qwen3.8-Flash`（`is_free:true`、`price_factor:0`）、
`DeepSeek-Flash`（同）。二者 180K 上下文、支持视觉；Qwen3.8-Flash 为推理模型。

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

单账号：`./qoder2api login` 或面板「重新登录」走 PKCE device flow（S256 challenge + nonce；
poll 走 OpenAPI 域，未授权时返回 404 属正常 pending），凭据落盘
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
