"""
webui.py — Qoder2api 旁路路由：登录 / 健康 / 信息面板 / 签到用量

与 OpenAI 兼容主链路（server.py 的 /v1/*）分离：这里都是状态查询与运维入口，
不承载推理流量。由 server.py 在 app 就绪后 import 挂载（register_routes）。
"""
import logging
import time
from datetime import datetime, timezone

from flask import jsonify, request

from lanes import benefit, qoder_cosy

logger = logging.getLogger(__name__)

# 由 register_routes 注入（server.py 的运行配置，避免双份读 .env）
_cfg = {"api_key": "", "port": 0, "is_cn": True}


def register_routes(app, *, api_key: str, port: int, is_cn: bool) -> None:
    """把旁路路由挂到 app 上；cfg 供面板/签到使用。"""
    _cfg.update(api_key=api_key, port=port, is_cn=is_cn)

    # ── 登录（PKCE device flow，非阻塞） ──────────────────────────────────────
    @app.route("/login", methods=["GET", "POST"])
    def login():
        st = qoder_cosy.start_device_login()
        if st.get("url"):
            return jsonify({"status": st["status"], "message": "请在浏览器打开 url 完成授权",
                            "url": st["url"]})
        if st.get("status") == "pending":
            return jsonify({"status": "pending", "message": "已有登录流程进行中，请轮询 /login/status"})
        return jsonify(st), 500

    @app.route("/login/status", methods=["GET"])
    def login_status():
        return jsonify(qoder_cosy.login_state())

    # ── 健康检查 & 信息面板 ──────────────────────────────────────────────────
    @app.route("/health", methods=["GET"])
    def health():
        cred = qoder_cosy._load_cred_file()
        has_cred = bool(cred and (cred.get("access_token") or cred.get("security_oauth_token")))
        return jsonify({
            "status": "ok",
            "auth": "configured" if has_cred else "no credential (run: python oauth.py)",
            "models": len(qoder_cosy.list_model_ids()),
            "identity": "self-owned (credentials.json + PKCE device flow)",
            "time": datetime.now(timezone.utc).isoformat(),
        })

    @app.route("/", methods=["GET"])
    def index():
        cred = qoder_cosy._load_cred_file()
        has_cred = bool(cred and (cred.get("access_token") or cred.get("security_oauth_token")))
        return f"""<html><head><meta charset="utf-8"><title>Qoder2api</title>
<style>body{{font-family:system-ui;max-width:600px;margin:40px auto;padding:0 20px}}
h1{{color:#0d7377}} .ok{{color:#2a9d8f}} .warn{{color:#e76f51}}
code{{background:#f4f4f4;padding:2px 5px;border-radius:3px}}</style></head><body>
<h1>🤖 Qoder2api</h1>
<p>OpenAI 兼容的 Qoder 网关</p>
<h3>状态</h3>
<ul>
<li>上游: <code>gateway.qoder.com.cn</code></li>
<li>身份: 自持有凭证（credentials.json + PKCE device flow，与 CLI/env 无关）</li>
<li>认证: <span class="{'ok' if has_cred else 'warn'}">{'已配置' if has_cred else '无凭证（先运行 python oauth.py）'}</span></li>
<li>端口: <code>{_cfg['port']}</code></li>
</ul>
<h3>端点</h3>
<ul>
<li><code>POST /v1/chat/completions</code></li>
<li><code>POST /v1/completions</code></li>
<li><code>GET  /v1/models</code></li>
<li><code>GET  /health</code> · <code>GET  /login/status</code> · <code>GET  /login</code></li>
<li><code>POST /benefit/claim</code> · <code>GET /benefit/usage</code> · <code>POST /benefit/coffee</code></li>
</ul>
</body></html>"""

    # ── 签到 / 用量端点 ──────────────────────────────────────────────────────
    @app.route("/benefit/claim", methods=["POST"])
    def benefit_claim():
        """立即签到：领取 100 Credits"""
        return jsonify(benefit.claim_now(is_cn=_cfg["is_cn"]))

    @app.route("/benefit/usage", methods=["GET"])
    def benefit_usage():
        """查用量"""
        return jsonify(benefit.get_usage())

    @app.route("/benefit/coffee", methods=["POST"])
    def benefit_coffee():
        """立即抢领奶茶免单卡"""
        return jsonify(benefit.claim_coffee_now(is_cn=_cfg["is_cn"]))
