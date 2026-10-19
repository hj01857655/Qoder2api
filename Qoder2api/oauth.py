"""
oauth.py — Qoder CN PKCE device flow 登录（独立 CLI，对齐 magpie internal/qoder/oauth.go）

用法:
  python oauth.py            # 发起登录：打印授权 URL → 轮询 → 落盘 credentials.json
  python oauth.py --status   # 查看最近一次登录结果
  python oauth.py --open     # 同默认，并尝试用系统浏览器打开授权页

流程（与 magpie DeviceFlow 完全一致）:
  1. 本机生成 verifier（64B 随机）+ S256 challenge + nonce + machine_id
  2. 浏览器打开 https://qoder.cn/device/selectAccounts?... 授权
  3. 轮询 GET  openapi/api/v1/deviceToken/poll?nonce&verifier  → dt- 设备令牌
  4. 换取 POST openapi/api/v1/me/jobToken（Bearer dt-）        → jt- 聊天令牌
  5. 覆盖写本目录 credentials.json（tmp + replace 原子替换）

凭证归 oauth.py / qoder_cosy.py 共有；不读不写 CLI 的 ~/.qoder-cn。
"""
import argparse
import base64
import hashlib
import json
import os
import sys
import time
import uuid
from datetime import datetime
from urllib.parse import urlencode
from urllib.request import urlopen

OPENAPI_HOST = "https://openapi.qoder.com.cn"
WEB_HOST = "https://qoder.cn"
DEVICE_CLIENT_ID = "e883ade2-e6e3-4d6d-adf7-f92ceff5fdcb"  # Qoder CN CLI 生产 client_id
# me/jobToken 专用的 clientId —— 与上面的 device flow client_id 是两回事。
# 用 DEVICE_CLIENT_ID 换恒回 HTTP 400 BadRequest（2026-10-20 实测），用这个值 200。
JOB_TOKEN_CLIENT_ID = "732aef47-9cf2-46a2-95fe-4cebb5d0d1fa"
DEVICE_SELECT_ACCOUNTS_PATH = "/device/selectAccounts"
DEVICE_TOKEN_POLL_PATH = "/api/v1/deviceToken/poll"
ME_JOB_TOKEN_PATH = "/api/v1/me/jobToken"

SIGN_IN_TIMEOUT_S = 900  # 与 magpie SIGN_IN_TIMEOUT 一致
POLL_INTERVAL_S = 2

CRED_FILE = os.path.join(os.path.dirname(__file__), "credentials.json")
UA = "Qoder"


def _machine_id() -> str:
    """每进程一个稳定身份（简化 magpie 的每账号身份；落盘后会随凭证复用）。"""
    return str(uuid.uuid4())


def authorization(machine_id: str) -> tuple[str, str, str]:
    """→ (auth_url, verifier, nonce)。PKCE：verifier 本地留存，S256(challenge) 给页面。"""
    verifier = base64.urlsafe_b64encode(os.urandom(64)).decode("ascii").rstrip("=")
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()).decode("ascii").rstrip("=")
    nonce = str(uuid.uuid4())
    q = urlencode({
        "challenge": challenge,
        "challenge_method": "S256",
        "nonce": nonce,
        "machine_id": machine_id,
        "client_id": DEVICE_CLIENT_ID,
    })
    return f"{WEB_HOST}{DEVICE_SELECT_ACCOUNTS_PATH}?{q}", verifier, nonce


def _get_json(url: str, bearer: str = "", body: bytes | None = None) -> tuple[int, dict]:
    """GET/POST JSON。404 属正常（未授权时 poll 就返回 404），原样返回状态码。"""
    from urllib.request import Request
    from urllib.error import HTTPError
    req = Request(url, data=body, method="POST" if body else "GET")
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", UA)
    if body:
        req.add_header("Content-Type", "application/json")
    if bearer:
        req.add_header("Authorization", f"Bearer {bearer}")
    try:
        with urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read().decode("utf-8", "ignore") or "{}")
    except HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8", "ignore") or "{}")
        except (OSError, ValueError):
            return e.code, {}
    except OSError as e:
        return 0, {"error": str(e)}


def poll_device_token(nonce: str, verifier: str) -> dict | None:
    """200 且 token 非空即成功；否则每 POLL_INTERVAL_S 再试，至超时。"""
    q = urlencode({"nonce": nonce, "verifier": verifier, "challenge_method": "S256"})
    endpoint = f"{OPENAPI_HOST}{DEVICE_TOKEN_POLL_PATH}?{q}"
    deadline = time.time() + SIGN_IN_TIMEOUT_S
    while time.time() < deadline:
        status, data = _get_json(endpoint)
        if status == 200 and str(data.get("token") or "").strip():
            return data
        if status == 404:
            # 未授权时 poll 返回 404 Not found，正常等待
            pass
        else:
            print(f"[login] poll → HTTP {status}", file=sys.stderr, flush=True)
        time.sleep(POLL_INTERVAL_S)
    return None


def exchange_job_token(device_token: str) -> tuple[int, dict]:
    """dt- 设备令牌换 jt- 聊天令牌。失败时可退回 dt- 直接签名。

    clientId 必须是 JOB_TOKEN_CLIENT_ID：填 DEVICE_CLIENT_ID 会 HTTP 400 BadRequest。"""
    body = json.dumps({"clientId": JOB_TOKEN_CLIENT_ID}).encode("utf-8")
    return _get_json(f"{OPENAPI_HOST}{ME_JOB_TOKEN_PATH}", bearer=device_token, body=body)


def _expires_at(data: dict, in_ms: bool = False) -> int:
    """in_ms：expires_in 的单位是毫秒。jobToken 族全是毫秒（86400000 = 1 天），
    deviceToken 族是秒。按秒算毫秒会得到 1000 天 → 永远不续期。
    不能靠数值大小猜（1 天的毫秒值比 30 天的秒值还大），只能按响应类型指定。"""
    for key in ("expires_at", "expiresAt", "expire_time"):
        v = data.get(key)
        if isinstance(v, (int, float)) and v:
            return int(v / 1000) if v > 1e11 else int(v)
        if isinstance(v, str) and v:
            try:
                return int(datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp())
            except ValueError:
                pass
    for key in ("expires_in", "expiresIn"):
        v = data.get(key)
        if isinstance(v, (int, float)) and v > 0:
            return int(time.time() + (v / 1000 if in_ms else v))
    return 0


def save_credentials(cred: dict) -> None:
    tmp = CRED_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cred, f, ensure_ascii=False, indent=2)
    os.replace(tmp, CRED_FILE)


def sign_in() -> dict | None:
    machine_id = _machine_id()
    url, verifier, nonce = authorization(machine_id)
    print("[login] 请在浏览器打开并授权（15 分钟内有效）:", flush=True)
    print(f"  {url}", flush=True)

    dt = poll_device_token(nonce, verifier)
    if dt is None:
        print("[login] 授权超时或被拒绝", file=sys.stderr, flush=True)
        return None

    cred = {
        "source": "device",
        "machine_id": machine_id,
        "token_type": "device",
        "security_oauth_token": dt["token"],
        "access_token": dt["token"],
        "refresh_token": dt.get("refresh_token") or "",
        "expire_time": _expires_at(dt),
        "uid": str(dt.get("user_id") or dt.get("uid") or ""),
    }

    # COSY 签名头需要 name/email/user blob，授权后立即查 userinfo 补齐
    status, ui = _get_json(f"{OPENAPI_HOST}/api/v1/userinfo", bearer=cred["access_token"])
    if status == 200:
        for key in ("email", "name"):
            if ui.get(key):
                cred[key] = ui[key]
        if not cred["uid"]:
            cred["uid"] = str(ui.get("id") or ui.get("user_id") or ui.get("uid") or "")
    else:
        print(f"[login] userinfo → HTTP {status}（name/email 缺失可能影响签名）", flush=True)

    status, jr = exchange_job_token(cred["access_token"])
    if status == 200 and str(jr.get("token") or "").strip():
        cred["token_type"] = "job"
        cred["security_oauth_token"] = jr["token"]
        cred["access_token"] = jr["token"]
        # **不能覆盖 refresh_token**：drt- 是 30 天/1 年的长效登录态，
        # 而 jobToken 响应里的 jrt- 只活 2 天。顶掉之后 2 天内就再也刷不回来了。
        if jr.get("refresh_token"):
            cred["job_refresh_token"] = jr["refresh_token"]
        exp = _expires_at(jr, in_ms=True)
        if exp:
            cred["expire_time"] = exp
        ref_exp = _expires_at(jr, "refresh_token_", in_ms=True)
        if ref_exp:
            cred["job_refresh_token_expire_time"] = ref_exp
        print("[login] 已换到 job token", flush=True)
    else:
        print(f"[login] job token 未换到（HTTP {status}），按 device token 签名", flush=True)

    save_credentials(cred)
    print(f"[login] 凭证已写入 {CRED_FILE}", flush=True)
    return cred


def main() -> int:
    ap = argparse.ArgumentParser(description="Qoder CN device flow 登录")
    ap.add_argument("--status", action="store_true", help="查看 credentials.json 概要")
    ap.add_argument("--open", action="store_true", help="用系统浏览器打开授权页")
    args = ap.parse_args()

    if args.status:
        try:
            with open(CRED_FILE, encoding="utf-8") as f:
                cred = json.load(f)
        except (OSError, ValueError):
            print("未登录（无 credentials.json）")
            return 1
        exp = cred.get("expire_time") or 0
        left = int((exp - time.time()) / 60) if exp else None
        print("email:", cred.get("email") or "?")
        print("token_type:", cred.get("token_type"), "| uid:", cred.get("uid") or "?")
        print("expire:", cred.get("expire_time"), f"（剩 {left} min）" if left else "（未知）")
        print("refresh_token:", "有" if cred.get("refresh_token") else "无")
        return 0

    cred = sign_in()
    if args.open and cred is None:
        pass
    if cred:
        print("登录成功:", cred.get("email") or cred.get("uid") or "?")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
