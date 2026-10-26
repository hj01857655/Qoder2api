# Qoder2api (Go)

![Go](https://img.shields.io/badge/Go-1.24-00ADD8?logo=go&logoColor=white) ![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey) ![Type](https://img.shields.io/badge/type-API%20Gateway-blue)

Qoder 转 OpenAI / Anthropic 兼容 API 的 Go 网关实现，支持页面登录。

## 构建

```bash
go build -o qoder2api .
```

## 运行

| 环境变量 | 说明 |
|---|---|
| `API_KEY` | 客户端鉴权密钥 |
| `HOST` | 监听地址，默认 `127.0.0.1`（Docker 部署设为 `0.0.0.0`） |
| `PORT` | 监听端口，默认 `8388` |
| `QODER_OPENAPI_HOST` | OpenAPI 上游地址覆盖 |
| `QODER_GATEWAY_HOST` | 网关上游地址覆盖 |
| `QODER_WEB_HOST` | Web 上游地址覆盖 |

## 接口

- `GET /health` — 健康检查
- `GET /v1/models` — 模型列表
- `POST /v1/chat/completions`、`POST /v1/completions` — OpenAI 兼容
- `POST /v1/messages` — Anthropic Messages 兼容
- `POST /v1/responses` — OpenAI Responses 兼容
- `GET /login`、`GET /login/status` — 页面登录与状态轮询

## Docker 部署

```bash
# 配置环境变量后启动
cp .env.example .env   # 按需填写
docker compose up -d
```

镜像同时发布到 GHCR：`ghcr.io/hj01857655/hj01857655/Qoder2api`（跟随 v* 标签发布，含 latest，linux/amd64 + linux/arm64）。

二进制发版：推送 `v*` 标签后 Actions 自动构建 linux / windows / darwin 的 amd64 + arm64 六平台产物并发布 Release。
