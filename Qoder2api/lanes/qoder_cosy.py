"""
qoder_cosy.py — Qoder COSY 协议直接 API 调用

协议逆向自 yetone/magpie internal/qoder + CLIProxyAPI (MIT)。
不经过 CLI，直接用 COSY 签名调推理端点。
凭证只走一个文件：本目录 credentials.json（PKCE device flow 生成，QODER_PERSIST=0 关闭）；
env 只存配置不含任何令牌；临近到期（<5min）与上游 401/403 都走续期并覆盖写回，
不读也不写 CLI 的 ~/.qoder-cn/.auth。

关键修正（对齐 magpie）：
- COSY_VERSION: 1.1.49（旧 0.1.43）
- Cosy-ClientType: 10（旧 5）
- Cosy-Data-Policy: disagree（旧 AGREE）
- Cosy-MachineToken/ClientIp = machineId（旧用 runtime-info.exe 的真实 token）
- user blob: {uid, aid:"", name, email, security_oauth_token}（旧多一堆字段）
- 请求体: 完整结构 {parameters, business, agent_id, model_config, system, messages}
- 签名 path: 去掉 /algo 前缀
"""
import base64
import hashlib
import json
import os
import platform
import re
import socket
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Iterator

import requests
import urllib3
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA

urllib3.disable_warnings()


class UpstreamError(RuntimeError):
    """上游返回非 200 / 请求失败，携带可透传给客户端的 HTTP 状态码"""

    def __init__(self, status: int, message: str):
        super().__init__(f"HTTP {status}: {message}")
        self.status = status


class ModelNotAllowed(UpstreamError):
    """模型不在限免范围 / 未知模型 —— 本地判定，根本没发上游请求

    单独成类是为了让路由层能把 message 原样给客户端（不带 "HTTP 400:" 前缀），
    而真正的上游错误仍沿用 UpstreamError 的带前缀格式（日志里那个前缀有用）。
    """

    def __init__(self, message: str):
        super().__init__(400, message)
        self.message = message          # 原文留一份，客户端用这个

    def __str__(self) -> str:
        return self.message

# ── 端点 ──────────────────────────────────────────────────────────────────────
GATEWAY_HOST = "https://gateway.qoder.com.cn"
CHAT_PATH = "/algo/api/v2/service/pro/sse/agent_chat_generation"
CHAT_QUERY = "?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1"
MODELS_PATH = "/algo/api/v2/model/list?Encode=1"

# ── 协议常量（对齐 magpie） ───────────────────────────────────────────────────
COSY_VERSION = "1.1.49"
QODER_SYS = "You are a Qoder agent. Use the instructions below and the tools available to you to assist the user."

# RSA 1024-bit 公钥（与 magpie cosy.go 完全一致）
RSA_PUBKEY_DER = base64.b64decode(
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDA8iMH5c02LilrsERw9t6Pv5Nc"
    "4k6Pz1EaDicBMpdpxKduSZu5OANqUq8er4GM95omAGIOPOh+Nx0spthYA2BqGz+l"
    "6HRkPJ7S236FZz73In/KVuLnwI8JJ2CbuJap8kvheCCZpmAWpb/cPx/3Vr/J6I17"
    "XcW+ML9FoCI6AOvOzwIDAQAB"
)

# 自定义 Base64 字母表（与 magpie codec.go 完全一致）
ALPHABET = "_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!"
STD_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_C2S = {ALPHABET[i]: STD_B64[i] for i in range(64)}
_S2C = {STD_B64[i]: ALPHABET[i] for i in range(64)}
_C2S["$"] = "="
_S2C["="] = "$"

# ── 自定义 Base64 编解码 ────────────────────────────────────────────────────
def qoder_encode(plaintext: bytes) -> str:
    """UTF8 → 标准 base64 → 首尾 1/3 交换 → 映射自定义字母表"""
    std = base64.b64encode(plaintext).decode("ascii")
    n = len(std)
    t = n // 3
    swapped = std[n - t:] + std[t:n - t] + std[:t]
    return "".join(_S2C.get(c, c) for c in swapped)


def qoder_decode(encoded: str) -> bytes:
    """自定义字母表 → 标准 base64 → 反交换 → 解码"""
    mapped = "".join(_C2S.get(c, c) for c in encoded)
    n = len(mapped)
    t = n // 3
    std = mapped[n - t:] + mapped[t:n - t] + mapped[:t]
    return base64.b64decode(std)


# ── 签名 ──────────────────────────────────────────────────────────────────────
def _md5_hex(s: str) -> str:
    return hashlib.md5(s.encode("utf-8")).hexdigest()


def sign_request(payload_b64: str, cosy_key: str, cosy_date: str,
                 body: str, path: str) -> str:
    """MD5(payload\\ncosyKey\\ndate\\nbody\\npath)"""
    return _md5_hex(f"{payload_b64}\n{cosy_key}\n{cosy_date}\n{body}\n{path}")


# ── 机器 OS 标识（对齐 magpie MachineOS()） ──────────────────────────────────
def machine_os() -> str:
    arch = {"amd64": "x86_64", "x86": "x86", "arm64": "aarch64"}.get(platform.machine().lower(), platform.machine().lower())
    os_name = "win32" if platform.system() == "Windows" else platform.system().lower()
    return f"{arch}_{os_name}"


# ── 身份与凭证（唯一凭证文件 credentials.json；.env 只存配置不含令牌，不读不写 CLI 的 ~/.qoder-cn） ──
_cached_identity = None
_cached_machine_id = None
# 一个进程一个 machine_id：引导、签名头、续期都用它（magpie 是每账号一个，存它自己的 store）
_PROCESS_MACHINE_ID = str(uuid.uuid4())

OPENAPI_HOST = "https://openapi.qoder.com.cn"
WEB_HOST = "https://qoder.cn"
# Qoder CN CLI 生产环境的 device flow client_id（magpie SITES["qoder-cn"]）
DEVICE_CLIENT_ID = "e883ade2-e6e3-4d6d-adf7-f92ceff5fdcb"
# /api/v1/me/jobToken 要的 clientId —— **和上面那个不是一回事，别混用**。
# 拿 DEVICE_CLIENT_ID 去换一直 HTTP 400 {"errorCode":"BadRequest"}（2026-10-20 实测），
# 换成这个固定 UUID 立刻 200 换到 jt-。它大概是「推理客户端类型」的注册标识，
# 语义不明但 23 个独立仓库都照抄同一个值，照抄即可，不要"优化"成随机值或省略。
JOB_TOKEN_CLIENT_ID = "732aef47-9cf2-46a2-95fe-4cebb5d0d1fa"
ME_JOB_TOKEN_PATH = "/api/v1/me/jobToken"
JOB_REFRESH_PATH = "/api/v1/jobToken/refresh"
DEVICE_POLL_PATH = "/api/v1/deviceToken/poll"
DEVICE_REFRESH_PATH = "/api/v1/deviceToken/refresh"
USERINFO_PATH = "/api/v1/userinfo"
REFRESH_LEAD_S = 300        # 距到期不足 5min 先刷再发（magpie REFRESH_LEAD）
SIGN_IN_TIMEOUT_S = 900     # device flow 等待授权（magpie SIGN_IN_TIMEOUT）
SIGN_IN_POLL_S = 2


# ── 唯一凭证文件（轮换后覆盖写；删除即重新登录，/login 可非阻塞重登） ──────────
CRED_FILE = os.path.join(os.path.dirname(__file__), "credentials.json")
_PERSIST = os.environ.get("QODER_PERSIST", "1").strip() != "0"


def _save_cred(cred: dict) -> None:
    """原子落盘（tmp + replace）。refresh_token 轮换，任何成功取得/续期的凭证都覆盖写。"""
    if not _PERSIST or not cred:
        return
    if not (cred.get("access_token") or cred.get("security_oauth_token")):
        return
    tmp = CRED_FILE + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cred, f, ensure_ascii=False, indent=2)
        os.replace(tmp, CRED_FILE)
    except OSError as e:
        print(f"[qoder_cosy] 凭证落盘失败: {e}", flush=True)


def _load_cred_file() -> dict | None:
    if not _PERSIST:
        return None
    try:
        with open(CRED_FILE, encoding="utf-8") as f:
            cred = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(cred, dict):
        return None
    if not (cred.get("access_token") or cred.get("security_oauth_token")):
        return None
    return cred


# ── 非阻塞登录（/login 路由用）：后台跑 device flow，状态可查 ──────────────────
_LOGIN_STATE = {"status": "idle", "url": None, "error": None, "email": None}
_LOGIN_LOCK = threading.Lock()


def login_state() -> dict:
    return dict(_LOGIN_STATE)


def start_device_login() -> dict:
    """非阻塞发起 device flow 登录；浏览器打开返回的 url 授权，/login/status 轮询结果。"""
    with _LOGIN_LOCK:
        if _LOGIN_STATE.get("status") == "pending":
            return dict(_LOGIN_STATE)
        _LOGIN_STATE.update(status="pending", url=None, error=None, email=None)

    def _run():
        global _cached_identity, _cached_machine_id
        try:
            cred = _device_flow_sign_in(state=_LOGIN_STATE)
            if cred:
                _cached_machine_id = cred.get("machine_id") or _PROCESS_MACHINE_ID
                cred["machine_id"] = _cached_machine_id
                _cached_identity = cred
                _save_cred(cred)
                _LOGIN_STATE.update(status="ok", email=cred.get("email") or "", url=None)
            else:
                _LOGIN_STATE.update(status="failed", error="授权超时或被拒绝")
        except Exception as e:  # noqa: BLE001 — 登录线程不拖垮服务
            _LOGIN_STATE.update(status="failed", error=f"{type(e).__name__}: {e}")

    threading.Thread(target=_run, daemon=True).start()
    return dict(_LOGIN_STATE)


OPENAPI_RETRY_S = 1.0        # openapi 偶发 TLS 抖动（实测 UNEXPECTED_EOF 后重试即通）


def _err_text(data: dict) -> str:
    """非 2xx 的拒因：CLI 侧按 errorMessage/error_message/message/error 取值"""
    for key in ("errorMessage", "error_message", "message", "error", "errorCode", "code"):
        v = data.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()[:200]
    return ""


def _request(method: str, path: str, *, json_body: dict | None = None,
             query: dict | None = None, bearer: str = "") -> tuple[int, dict]:
    headers = {"Accept": "application/json", "User-Agent": "Qoder"}
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    last = ""
    for attempt in range(2):
        try:
            r = requests.request(method, f"{OPENAPI_HOST}{path}", json=json_body, params=query,
                                 headers=headers, timeout=15, verify=True)
            try:
                data = r.json()
            except ValueError:
                data = {}
            if not r.ok:
                print(f"[qoder_cosy] {path} → HTTP {r.status_code} {_err_text(data) or (r.text or '')[:200]}",
                      flush=True)
            return r.status_code, data if isinstance(data, dict) else {}
        except requests.exceptions.RequestException as e:
            last = type(e).__name__
            if attempt == 0:
                time.sleep(OPENAPI_RETRY_S)
    print(f"[qoder_cosy] {path} 请求异常: {last}", flush=True)
    return 0, {}


def _openapi_post(path: str, body: dict, bearer: str = "") -> tuple[int, dict]:
    return _request("POST", path, json_body=body, bearer=bearer)


def _openapi_get(path: str, query: dict, bearer: str = "") -> tuple[int, dict]:
    return _request("GET", path, query=query, bearer=bearer)


def _expires_at(data: dict, prefix: str = "", in_ms: bool = False) -> int:
    """expires_at 支持 epoch 秒/毫秒/ISO；缺则用 expires_in 换算；都缺返回 0（未知）

    in_ms：expires_in 的单位是**毫秒**。jobToken 族全是毫秒（实测 86400000 = 1 天、
    refresh_token_expires_in 172800000 = 2 天），当秒算会得到 1000 天，
    于是永远不会续期。deviceToken 族是秒——所以这个必须由调用方按响应类型指定，
    不能靠数值大小猜（1 天毫秒 8.64e7 比 30 天秒 2.59e6 还大）。"""
    for key in (f"{prefix}expires_at", f"{prefix}expiresAt"):
        v = data.get(key)
        if isinstance(v, (int, float)) and v:
            return int(v / 1000) if v > 1e11 else int(v)
        if isinstance(v, str) and v:
            try:
                return int(datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp())
            except ValueError:
                pass
    for key in (f"{prefix}expires_in", f"{prefix}expiresIn"):
        v = data.get(key)
        if isinstance(v, (int, float)) and v > 0:
            return int(time.time() + (v / 1000 if in_ms else v))
    return 0


def _cred_applied(data: dict, base: dict, token_type: str) -> dict | None:
    """把兑换/续期响应并进凭证；无 token 视为失败。refresh_token 会轮换，必须整体覆盖

    token_type="job" 时走 jobToken 分支：单位是毫秒，且 **不能覆盖 refresh_token**。
    原因：文件里那个 `drt-` 是 30 天/1 年的长效登录态，而 jobToken 响应带的
    `jrt-` 只活 2 天。直接覆盖会让 2 天后连用户都刷不回来（要重新走浏览器授权）。
    所以把 job 族的刷新凭据单独存在 `job_refresh_token`，与长效的分开。"""
    job = token_type == "job"
    tok = data.get("token") or data.get("device_token") or data.get("access_token") or ""
    if not tok:
        return None
    cred = dict(base)
    cred["security_oauth_token"] = tok
    cred["access_token"] = tok
    cred["token_type"] = token_type
    exp = _expires_at(data, in_ms=job)
    if exp:
        cred["expire_time"] = exp
    ref_exp = _expires_at(data, "refresh_token_", in_ms=job)
    if ref_exp:
        cred["refresh_token_expire_time" if not job else "job_refresh_token_expire_time"] = ref_exp
    if data.get("refresh_token"):
        if job:
            # 别动凭长效登录态的 refresh_token
            cred["job_refresh_token"] = data["refresh_token"]
        else:
            cred["refresh_token"] = data["refresh_token"]
    for key in ("uid", "name", "email"):
        if data.get(key):
            cred[key] = data[key]
    return cred


def _device_flow_sign_in(state: dict | None = None) -> dict | None:
    """PKCE device flow：复用 oauth.py（独立 CLI，对齐 magpie internal/qoder/oauth.go）。
    本机出 verifier/nonce/machine_id，浏览器授权后轮询取 device token，再换 job token。
    阻塞至多 SIGN_IN_TIMEOUT_S。"""
    import oauth
    machine_id = _PROCESS_MACHINE_ID
    url, verifier, nonce = oauth.authorization(machine_id)
    print(f"[qoder_cosy] 无本地凭证（credentials.json 缺失或不可用），需登录。请在浏览器授权（{SIGN_IN_TIMEOUT_S}s 内）:\n  {url}", flush=True)
    if state is not None:
        state.update(url=url)

    dt = oauth.poll_device_token(nonce, verifier)
    if dt is None:
        print("[qoder_cosy] device flow 超时或被拒", flush=True)
        return None

    cred = _cred_applied(dt, {"source": "device", "machine_id": machine_id,
                              "uid": str(dt.get("user_id") or "")}, "device")
    if not cred:
        return None
    status, ui = _openapi_get(USERINFO_PATH, {}, dt["token"])
    if status == 200:
        for key in ("email", "name"):
            if ui.get(key):
                cred[key] = ui[key]
        if not cred.get("uid"):
            cred["uid"] = str(ui.get("id") or ui.get("user_id") or ui.get("uid") or "")

    # 换 job token。**clientId 必须是 JOB_TOKEN_CLIENT_ID**：拿 device flow 的
    # client_id 去换恒回 HTTP 400 BadRequest（2026-10-20 实测），换对了立刻 200。
    # 换不到也无妨——device token 同样能签名，只是少了那层短期凭据。
    status, jr = _openapi_post(ME_JOB_TOKEN_PATH, {"clientId": JOB_TOKEN_CLIENT_ID}, bearer=dt["token"])
    job = _cred_applied(jr, cred, "job") if status == 200 else None
    if job:
        return job
    print(f"[qoder_cosy] job token 未换到（HTTP {status}），按 device token 签名", flush=True)
    return cred


def _bootstrap() -> dict | None:
    """凭证引导：credentials.json 缺失或不可用时走浏览器 device flow 登录。
    此时会阻塞等待授权（至多 SIGN_IN_TIMEOUT_S）；首次部署可先 python oauth.py 预登录生成落盘凭证。"""
    return _device_flow_sign_in()


def _refresh_credential(cred: dict) -> dict | None:
    """续期。两套凭据各有各的刷新口，**不能互相顶替**：

      deviceToken/refresh  ← drt-（rotation，长效 30 天/1 年）
      jobToken/refresh     ← jrt-（rotation，只活 2 天）

    用 drt- 去打 jobToken/refresh 必然 400（那是另一种 refresh token），
    反过来同理。所以先按当前 token_type 走自己的口，都失败再退回长效的
    device 续期 + 重新换一次 job token。"""
    # 1) 先刷当前这套。job 用 jrt-，device 用 drt-。
    tries = []
    if cred.get("token_type") == "job" and cred.get("job_refresh_token"):
        tries.append((JOB_REFRESH_PATH, "job", cred["job_refresh_token"]))
    if cred.get("refresh_token"):
        tries.append((DEVICE_REFRESH_PATH, "device", cred["refresh_token"]))
    for path, ttype, rt in tries:
        status, data = _openapi_post(path, {"refresh_token": rt})
        if status != 200:
            print(f"[qoder_cosy] 续期 {path} → HTTP {status}", flush=True)
            continue
        new = _cred_applied(data, cred, ttype)
        if not new:
            print(f"[qoder_cosy] 续期 {path} 响应无 token", flush=True)
            continue
        print(f"[qoder_cosy] 凭证已续期（{path}）", flush=True)
        if ttype == "device" and new.get("token_type") != "job":
            # device token 刷成功了，但签名用的是 job——顺手再换一个，换不到就用 dt-。
            new = _renew_job_from_device(new)
        _save_cred(new)
        return new
    return None


def _renew_job_from_device(cred: dict) -> dict:
    """拿刚续好的 device token 换一个新 job token；失败原样返回（dt- 也能签名）"""
    dt = cred.get("access_token") or ""
    if not dt.startswith("dt-"):
        return cred
    status, jr = _openapi_post(ME_JOB_TOKEN_PATH, {"clientId": JOB_TOKEN_CLIENT_ID}, bearer=dt)
    job = _cred_applied(jr, cred, "job") if status == 200 else None
    if job:
        print("[qoder_cosy] 已用 device token 重新换到 job token", flush=True)
        return job
    return cred


def _expiring(cred: dict) -> bool:
    exp = cred.get("expire_time") or 0
    return bool(exp) and exp - int(time.time()) < REFRESH_LEAD_S


def load_identity(force_refresh: bool = False) -> dict:
    """取自有凭证：内存态（临近到期先续期）→ credentials.json → device flow 登录。
    force_refresh 用于上游 401/403：跳过缓存，续期失败即重新登录。"""
    global _cached_identity, _cached_machine_id
    if _cached_identity and not force_refresh and not _expiring(_cached_identity):
        return _cached_identity

    cred = _cached_identity
    if cred and (force_refresh or _expiring(cred)):
        cred = _refresh_credential(cred)
    if not cred:
        cred = _load_cred_file()
        if cred and _expiring(cred):
            refreshed = _refresh_credential(cred)
            cred = refreshed or cred
        if cred:
            print("[qoder_cosy] 已从 credentials.json 恢复凭证", flush=True)
    if not cred:
        cred = _bootstrap()
    if not cred:
        raise RuntimeError("no usable Qoder credential (credentials.json missing/unusable and device flow failed)")

    _cached_identity = cred
    _cached_machine_id = cred.get("machine_id") or _PROCESS_MACHINE_ID
    _cached_identity["machine_id"] = _cached_machine_id
    return _cached_identity


def invalidate_identity() -> None:
    """丢弃进程内凭证缓存（仅本进程，无任何文件写入）"""
    global _cached_identity, _cached_machine_id
    _cached_identity = None
    _cached_machine_id = None


def reauthenticate() -> bool:
    """上游 401/403 后强制重解析：先续期，续期被拒则 device flow 重登录"""
    try:
        load_identity(force_refresh=True)
    except Exception as e:
        invalidate_identity()
        print(f"[qoder_cosy] 凭证重取失败: {type(e).__name__}", flush=True)
        return False
    return True


def get_machine_id() -> str:
    """获取 machine_id（load_identity 时缓存）"""
    if not _cached_machine_id:
        load_identity()
    return _cached_machine_id


# ── COSY 头构建（对齐 magpie cosy.go BuildCosyHeaders） ──────────────────────
def build_cosy_headers(url: str, body: str, timestamp: int = 0) -> dict:
    """
    构建 COSY 签名请求头。

    url: 完整请求 URL（用于提取签名 path）
    body: 已编码的 wire body（自定义 base64 后的字符串）
    """
    identity = load_identity()
    machine_id = get_machine_id()

    # 1. User blob: AES-128-CBC 加密，key=IV=UUID 前 16 hex
    blob_data = {
        "uid": identity.get("uid", ""),
        "aid": "",
        "name": identity.get("name", ""),
        "email": identity.get("email", ""),
        "security_oauth_token": identity["security_oauth_token"],
    }
    blob_json = json.dumps(blob_data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    aes_key = uuid.uuid4().hex[:16].encode("ascii")
    pad_len = 16 - len(blob_json) % 16
    blob_padded = blob_json + bytes([pad_len]) * pad_len
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv=aes_key)
    info_b64 = base64.b64encode(aes_cipher.encrypt(blob_padded)).decode("ascii")

    # 2. RSA 加密 AES key
    rsa_key = RSA.import_key(RSA_PUBKEY_DER)
    key_b64 = base64.b64encode(PKCS1_v1_5.new(rsa_key).encrypt(aes_key)).decode("ascii")

    # 3. Payload
    payload_obj = {
        "version": "v1",
        "requestId": str(uuid.uuid4()),
        "info": info_b64,
        "cosyVersion": COSY_VERSION,
        "ideVersion": "",
    }
    payload_b64 = base64.b64encode(
        json.dumps(payload_obj, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")

    # 4. 签名 path: 去掉 /algo 前缀
    from urllib.parse import urlparse
    path = urlparse(url).path
    if path.startswith("/algo"):
        path = path[len("/algo"):]

    # 5. 签名
    if timestamp == 0:
        timestamp = int(time.time())
    cosy_date = str(timestamp)
    sig = sign_request(payload_b64, key_b64, cosy_date, body, path)

    # 6. 完整头集（对齐 magpie）
    return {
        "Accept": "text/event-stream",
        "Accept-Encoding": "identity",
        "Content-Type": "application/json",
        "Authorization": f"Bearer COSY.{payload_b64}.{sig}",
        "Cosy-Business-Product": "app",
        "Cosy-Business-Type": "agent",
        "Cosy-ClientIp": machine_id,
        "Cosy-ClientType": "10",
        "Cosy-Data-Policy": "disagree",
        "Cosy-Date": cosy_date,
        "Cosy-Key": key_b64,
        "Cosy-MachineId": machine_id,
        "Cosy-MachineToken": machine_id,
        "Cosy-MachineType": "5",
        "Cosy-MachineOS": machine_os(),
        "Cosy-Scene": "app",
        "Cosy-User": identity["uid"],
        "Cosy-Version": COSY_VERSION,
        "Login-Version": "v2",
    }


# ── 模型列表 ──────────────────────────────────────────────────────────────────
_model_cache = None
_model_cache_time = 0
MODEL_CACHE_TTL = 300  # 5 分钟

# 内置模型列表（无法从 API 获取时兜底）——**只放限免的那两个**
#
# 2026-10-20 按 /algo/api/v2/model/list 的 price_factor 核过：只有
# Qwen3.8-Flash 和 DeepSeek-Flash 是 0.0（原价 0.1），其余 11 个都计费。
# 这里**故意只留这两个**：兜底名单一旦包含收费模型，网络抖动时就会静默把
# 付费档推给客户端，而且错的方向最坏（用户以为免费，实际扣额度）。
# 宁可漏推荐，不可错推荐。
#
# 注意：这是写死的快照，上游改了收费策略它不会跟着变。它是「拉不到列表时
# 不得不给点什么」的最后手段，不是事实来源——真相永远在 model/list 的
# price_factor 里。
FALLBACK_MODELS = [
    "Qwen3.8-Flash", "DeepSeek-Flash",
]


def fetch_models() -> list[dict]:
    """从 /algo/api/v2/model/list?Encode=1 获取模型列表，带 COSY 签名"""
    global _model_cache, _model_cache_time
    now = time.time()
    if _model_cache and now - _model_cache_time < MODEL_CACHE_TTL:
        return _model_cache

    url = f"{GATEWAY_HOST}{MODELS_PATH}"

    resp = None
    for attempt in range(2):
        headers = build_cosy_headers(url, "")
        headers["Accept"] = "application/json"
        try:
            resp = requests.get(url, headers=headers, timeout=15, verify=True)
        except requests.exceptions.RequestException as e:
            print(f"[qoder_cosy] 模型列表请求异常: {e}", flush=True)
            return _model_cache or []
        if resp.status_code in (401, 403) and attempt == 0:
            # 10605 是业务排队限流（isQueued/waitTime），换凭证没用：不续期、
            # 不在这里重发（会放大请求量），直接抛给 server 层按 waitTime 睡等重试
            if "10605" in resp.text[:500]:
                break
            reauthenticate()
            continue
        break

    if resp.status_code != 200:
        print(f"[qoder_cosy] 模型列表获取失败: HTTP {resp.status_code}", flush=True)
        return _model_cache or []

    data = resp.json()
    models = []
    for raw in data.get("chat", []):
        if not raw.get("enable", False):
            continue
        key = raw.get("key", "")
        if key in ("", "auto", "default"):
            continue
        models.append({
            "key": key,
            "name": raw.get("display_name", key),
            "config": raw,  # 完整原始配置，用于请求体的 model_config
            "is_reasoning": raw.get("is_reasoning", False),
            "max_input_tokens": raw.get("max_input_tokens", 0),
        })

    if models:
        _model_cache = models
        _model_cache_time = now
        print(f"[qoder_cosy] 获取到 {len(models)} 个模型", flush=True)
    return models


def _price_factor(m: dict) -> float | None:
    """取模型倍率（price_factor）；取不到返回 None

    实测当前全是 JSON number（0.0 / 0.1 / …），但上游换类型不是没可能——
    字符串 "0.0" 用 `== 0` 比是 False，会把免费模型误判成收费。统一转 float。
    """
    cfg = m.get("config") or {}
    v = cfg.get("price_factor")
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _is_free_model(m: dict) -> bool:
    """模型是否限免：price_factor 为 0 或 is_free 为 true

    2026-10-20 从 /algo/api/v2/model/list 原始配置核出：Qwen3.8-Flash 与
    DeepSeek-Flash 两个满足（price_factor=0.0 + is_free=true，原价 0.1），
    其余 11 个均按 price_factor 计费。
    """
    cfg = m.get("config") or {}
    if cfg.get("is_free"):
        return True
    pf = _price_factor(m)
    return pf is not None and pf == 0.0


def model_entry(m: dict) -> dict:
    """给 /v1/models 用的一条记录：在标准字段外附带倍率信息

    OpenAI 客户端会忽略不认识的字段，所以多这两个不破坏兼容性；
    但人和面板就能看出「为什么列表里只有这些」，而不是面对一个空名单干瞪眼。
    """
    cfg = m.get("config") or {}
    return {
        "key": m["key"],
        "name": m["name"],
        "price_factor": _price_factor(m),
        "is_free": _is_free_model(m),
        "original_price_factor": cfg.get("original_price_factor"),
        "context_window": cfg.get("max_input_tokens") or 0,
        "supports_vision": bool(cfg.get("is_vl")),
        "is_reasoning": bool(cfg.get("is_reasoning")),
    }


def list_model_entries() -> list[dict]:
    """限免模型的完整信息（含倍率）；取不到上游列表时回落 FALLBACK_MODELS"""
    models = fetch_models()
    if models:
        free = [model_entry(m) for m in models if _is_free_model(m)]
        if free:
            return free
    return [{"key": n, "name": n, "price_factor": 0.0, "is_free": True,
             "original_price_factor": None, "context_window": 0,
             "supports_vision": False, "is_reasoning": False}
            for n in FALLBACK_MODELS]


def list_model_ids() -> list[str]:
    """返回模型 ID 列表（用显示名，客户端友好）——只输出限免模型

    列表里没有的模型，请求时也会被 ensure_free_model() 挡掉（见下）。
    两处一致，不会出现「列表里没有但能调」的落差。
    """
    return [e["name"] for e in list_model_entries()]


def resolve_model(model_key: str) -> dict | None:
    """按 key / display_name / 模糊 找到模型条目（含 price_factor 等元数据）

    与 find_model_config 的区别：后者只回 config（构建请求体要用），本函数回整条
    `{"key","name","config",...}`，因为判断收费与否要同时看 config 里的
    price_factor/is_free 和条目本身的 key/name。
    """
    models = fetch_models()
    lk = (model_key or "").strip().lower()
    if not lk:
        return None
    for m in models:                       # 精确 key
        if m["key"] == model_key:
            return m
    for m in models:                       # 精确显示名
        if m["name"] == model_key:
            return m
    for m in models:                       # 模糊（兼容客户端的大小写/别名）
        if lk in m["name"].lower() or lk in m["key"].lower():
            return m
    return None


def default_model_name() -> str:
    """客户端没填 model 时用的档：取限免名单第一个（当前是 Qwen3.8-Flash）

    不能给空串——上游 X-Model-Key 必填。也不给 "auto"——上游没有这个模型
    （实测 13 个 key 里没有 auto），填了只会返一个上游错误。
    """
    ids = list_model_ids()
    return ids[0] if ids else (FALLBACK_MODELS[0] if FALLBACK_MODELS else "")


def ensure_free_model(model_key: str) -> str:
    """校验模型是否限免，**返回实际要用的模型名**（空值会归一成默认档）

    为什么不放行付费档：`/v1/models` 只列限免的两个模型，客户端却可以硬编码
    一个付费模型照样调通——那等于把「免费」做成了看用户自觉。付费档会按
    price_factor 真扣额度（Kimi-K3 是 1.4 倍），而用户从列表上看不出来。

    三种情况一律拒绝，且**故意把原因写清楚**（哪个档、多少倍率、该用哪个）：
      1. 明确收费（price_factor > 0）
      2. 上游列表里根本没有（名字拼错 / 已下线）—— 不猜，直接报
      3. 拉不到列表（fetch_models 空）—— 只认 FALLBACK_MODELS

    第 3 种别理解成「暂时拿不到元数据就网开一面」：宁可拒绝也不要冒险放行
    一个可能收费的档。

    为什么返回名字而不是 None：调用方（四个路由 + 引擎）都需要处理「省略
    model」的情况。把归一化放在这里，调用方拿返回值直接用，不用各自复制
    一遍 `if not model.strip(): model = default_model_name()`。
    """
    # 空 model 不算错：OpenAI 协议里它是可选字段，很多客户端干脆不填。
    # 上游没有 "auto" 这个模型（13 个 key 里没有），空串更是必挂，
    # 所以统一落到默认限免档。
    if not (model_key or "").strip():
        return default_model_name()

    models = fetch_models()
    if not models:
        if model_key in FALLBACK_MODELS:
            return model_key
        raise ModelNotAllowed(
            f"模型 {model_key!r} 不可用（上游模型列表暂时取不到，仅允许 "
            f"{', '.join(FALLBACK_MODELS)}）")

    entry = resolve_model(model_key)
    if entry is None:
        avail = ", ".join(m["name"] for m in models if _is_free_model(m)) or "无"
        raise ModelNotAllowed(f"未知模型 {model_key!r}。当前可用（限免）：{avail}")
    if not _is_free_model(entry):
        pf = _price_factor(entry)
        avail = ", ".join(m["name"] for m in models if _is_free_model(m)) or "无"
        raise ModelNotAllowed(
            f"模型 {entry['name']!r} 不在限免范围（price_factor={pf}），"
            f"已拒绝以免扣额度。请改用：{avail}")
    return entry["name"]


def find_model_config(model_key: str) -> dict | None:
    """查找模型的完整配置（用于请求体 model_config）

    先精确匹配 key，再精确匹配 display_name，再模糊匹配。
    """
    models = fetch_models()
    # 精确匹配 key
    for m in models:
        if m["key"] == model_key:
            return m["config"]
    # 精确匹配 display_name
    for m in models:
        if m["name"] == model_key:
            return m["config"]
    # 模糊匹配 display_name
    lk = model_key.lower()
    for m in models:
        if lk in m["name"].lower() or lk in m["key"].lower():
            return m["config"]
    return None


# ── 请求体构建（对齐 magpie qoderBody） ──────────────────────────────────────
def _text_of(content) -> str:
    """从 OpenAI content 提取纯文本"""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(p.get("text", "") for p in content if isinstance(p, dict) and p.get("type") == "text")
    return ""


def _content_blocks(content) -> list[dict]:
    """OpenAI content → Qoder content blocks"""
    if isinstance(content, str):
        return [{"type": "text", "text": content}] if content else []
    if isinstance(content, list):
        blocks = []
        for p in content:
            if not isinstance(p, dict):
                continue
            if p.get("type") == "text" and p.get("text"):
                blocks.append({"type": "text", "text": p["text"]})
            elif p.get("type") == "image_url":
                url = p.get("image_url", {})
                if isinstance(url, dict):
                    url = url.get("url", "")
                if url:
                    blocks.append({"type": "image_url", "image_url": {"url": url}})
        return blocks
    return []


_THINK_TAG_RE = re.compile(r"</?think>")


def _strip_think_tags(text: str) -> str:
    """剥掉内联进正文的 think 模板标签（断开历史回显污染链）。"""
    return _THINK_TAG_RE.sub("", text) if text else text


def _qoder_messages(messages: list[dict]) -> list[dict]:
    """将 OpenAI messages 转为 Qoder 格式（跳过 system，保留 tool_calls / tool 结果）"""
    out = []
    for m in messages:
        role = m.get("role", "")
        if role in ("system", "developer"):
            continue
        if role == "tool":
            out.append({
                "role": "tool",
                "tool_call_id": m.get("tool_call_id", ""),
                "content": _content_blocks(_text_of(m.get("content", ""))),
            })
            continue
        entry = {"role": role, "content": _content_blocks(m.get("content", ""))}
        if role == "assistant" and entry["content"]:
            # 历史助手正文里的内联 think 标签剥掉，防止被污染的会话每轮回显；
            # 剥完只剩空白的 text 块直接丢弃（如 "\n</think>\n\n" 整条变空）
            entry["content"] = [
                {**b, "text": _strip_think_tags(b["text"])} for b in entry["content"]
            ]
            entry["content"] = [b for b in entry["content"] if b["text"].strip()]
        # 客户端回传思考时原样带上（协议出站也叫 reasoning_content，不发明新字段）
        if role == "assistant" and m.get("reasoning_content"):
            entry["reasoning_content"] = m["reasoning_content"]
        if role == "assistant" and m.get("tool_calls"):
            entry["tool_calls"] = [
                {
                    "id": tc.get("id", ""),
                    "type": tc.get("type", "function"),
                    "function": {
                        "name": (tc.get("function") or {}).get("name", ""),
                        "arguments": (tc.get("function") or {}).get("arguments", ""),
                    },
                }
                for tc in m["tool_calls"]
            ]
        if entry["content"] or entry.get("tool_calls"):
            out.append(entry)
    return out


# tool_choice 原样透传 OpenAI 值：CLI 在 Qoder 路径上用 protobuf Value 包装
# （string→stringValue、object→structValue，bundle/qoderclicn.js k3A @19413556）。
# {type:"any"}/{type:"tool"} 那套枚举属 Anthropic 适配器（同包 z0c @19524515），此处不适用。
def _tool_choice_wire(tc):
    """返回要送出的 tool_choice，None 表示不送。'none' 由调用方直接省略 tools 表达。"""
    if isinstance(tc, str) and tc in ("auto", "required"):
        return tc
    if isinstance(tc, dict) and tc.get("type") == "function":
        return tc
    return None


def build_request_body(chat: dict, model_config: dict | None) -> str:
    """
    构建 agent_chat_generation 请求体（plaintext JSON），返回编码后的 wire body。

    chat: OpenAI chat completion 请求
    model_config: 从模型列表获取的完整模型配置
    """
    messages = chat.get("messages", [])

    # 提取 system 消息
    system_text = "\n\n".join(
        _text_of(m["content"]) for m in messages
        if m.get("role") in ("system", "developer") and _text_of(m.get("content", ""))
    )
    sys_text = QODER_SYS + ("\n\n" + system_text if system_text else "")
    sys_block = {"type": "text", "text": sys_text}

    # 推理参数
    model_req = chat.get("model", "Auto")
    reasoning_effort = chat.get("reasoning_effort")
    max_tokens = chat.get("max_completion_tokens") or chat.get("max_tokens") or 32000

    # 判断是否推理模型
    is_reasoning = False
    if model_config:
        is_reasoning = model_config.get("is_reasoning", False)
        thinking_config = model_config.get("thinking_config", {})
        if thinking_config.get("enabled"):
            is_reasoning = True

    # 客户端可显式开关思考；未指定时按模型是否推理
    enable_thinking = chat.get("enable_thinking")
    if enable_thinking is None:
        enable_thinking = is_reasoning
    enable_thinking = bool(enable_thinking)

    params = {"enable_thinking": enable_thinking, "max_tokens": max_tokens}
    temperature = chat.get("temperature")
    if temperature is not None:
        params["temperature"] = temperature
    top_p = chat.get("top_p")
    if top_p is not None:
        params["top_p"] = top_p
    top_k = chat.get("top_k")
    if isinstance(top_k, int):
        params["top_k"] = top_k
    if reasoning_effort and enable_thinking:
        params["reasoning_effort"] = reasoning_effort
    # reasoning_budget_tokens：CLI 由 thinkingBudget 写入（h.reasoning_budget_tokens=o?.thinkingBudget @23318690），
    # 且只在思考开启时生效
    budget = chat.get("reasoning_budget_tokens")
    if isinstance(budget, int) and budget > 0 and enable_thinking:
        params["reasoning_budget_tokens"] = budget
    if chat.get("preserve_thinking"):
        params["preserve_thinking"] = True
    # context_length：CLI 在有 contextWindow 时写 parameters.context_length（@23318769）
    context_length = chat.get("context_length")
    if isinstance(context_length, int) and context_length > 0:
        params["context_length"] = context_length
    # tool_choice：CLI 写在 parameters 里（h.tool_choice=o.toolChoice @23318803），非顶层
    tc = _tool_choice_wire(chat.get("tool_choice"))
    if tc:
        params["tool_choice"] = tc

    # 请求体
    body = {
        "parameters": params,
        "business": {
            "product": "app",
            "version": COSY_VERSION,
            "type": "agent",
            "id": uuid.uuid4().hex,
            "name": "qoder2api session",
            "begin_at": int(time.time() * 1000),
            "stage": "start",
        },
        "agent_id": "agent_common",
        "task_id": "common",
        "session_type": "app",
        "model_config": model_config or {"key": model_req},
        "system": [sys_block],
        "messages": [{"role": "system", "content": [sys_block]}, *_qoder_messages(messages)],
    }

    # tools
    tools = chat.get("tools", [])
    if tools and chat.get("tool_choice") != "none":
        body["tools"] = [
            {
                "type": "function",
                "function": {
                    "name": t["function"]["name"],
                    "description": t["function"].get("description", ""),
                    "parameters": t["function"].get("parameters", {"type": "object", "properties": {}}),
                },
            }
            for t in tools
            if t.get("type") == "function" and t.get("function", {}).get("name")
        ]

    ptc = chat.get("parallel_tool_calls")
    if isinstance(ptc, bool):
        params["parallel_tool_calls"] = ptc

    plaintext = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return qoder_encode(plaintext)


# ── 推理调用 ──────────────────────────────────────────────────────────────────
def _iter_sse_lines(resp):
    """逐行产出 SSE，并把流正文阶段的传输层中断归一成 UpstreamError。

    requests.post 的异常在上面已经包成 UpstreamError，但 iter_lines 在读响应体
    时抛的是原生 ConnectionError / ChunkedEncodingError / Timeout（上游 120s 没
    吐首字节就是这条路径）。不转换的话，server 层「仅在未产出字节时重试」的判据
    根本看不到它，只会落进最外层的 except Exception，打出一条没有 rid 的堆栈。
    """
    try:
        for line in resp.iter_lines(decode_unicode=True):
            yield line
    except (requests.exceptions.ConnectionError,
            requests.exceptions.ChunkedEncodingError,
            requests.exceptions.Timeout) as error:
        # 措辞与 requests.post 那条保持一致，复用 server 的 _connect_wait 判据
        raise UpstreamError(502, f"upstream request failed: {error}") from error
    finally:
        resp.close()


class _ThinkSplitter:
    """跨 chunk 的 <think> 内联标签分流状态机。

    背景：Qoder 上游偶发不走 reasoning_content 结构化通道，把推理模板
    <think>…</think>（有时只有孤立的闭合标签）内联在 delta.content 里；
    直接透传会让客户端把标签当正文渲染并存进会话历史，之后每轮回显。

    规则：<think> 后内容归 reasoning，</think> 后回到正文；无配对的
    孤立标签按噪声丢弃；流尾可能跨 chunk 断开的残缺片段暂存，flush 冲刷。
    """

    OPEN = "<think>"
    CLOSE = "</think>"
    _HOLD = len(CLOSE) - 1  # 可能是标签前缀的最长尾部片段

    def __init__(self):
        self.in_think = False
        self._tail = ""       # 暂存的跨 chunk 残缺片段
        self._pending = []    # 待取用的 (kind, text) 有序段

    def feed(self, text):
        buf = self._tail + text
        self._tail = ""
        segs = []
        i = 0
        while i < len(buf):
            o, c = buf.find(self.OPEN, i), buf.find(self.CLOSE, i)
            if self.in_think:
                # think 段内：闭合标签翻出；再现的 <think> 是噪声，丢弃不翻状态
                if c < 0 or (0 <= o < c):
                    hit, tag, closing = o, self.OPEN, None
                else:
                    hit, tag, closing = c, self.CLOSE, True
            else:
                if o < 0:
                    hit, tag, closing = c, self.CLOSE, True
                elif c < 0 or o < c:
                    hit, tag, closing = o, self.OPEN, False
                else:
                    hit, tag, closing = c, self.CLOSE, True
            if hit < 0:
                # 无完整标签：仅暂存可能是标签前缀的尾部，其余按当前状态归属
                keep = 0
                for k in range(min(self._HOLD, len(buf) - i), 0, -1):
                    seg = buf[len(buf) - k:]
                    if self.OPEN.startswith(seg) or self.CLOSE.startswith(seg):
                        keep = k
                        break
                body = buf[i:len(buf) - keep]
                if body:
                    segs.append(("reasoning" if self.in_think else "content", body))
                self._tail = buf[len(buf) - keep:]
                break
            body = buf[i:hit]
            if body:
                segs.append(("reasoning" if self.in_think else "content", body))
            # 配对的开关标签翻转状态；错配/嵌套的孤立标签按噪声丢弃
            if closing is not None and closing == self.in_think:
                self.in_think = not self.in_think
            i = hit + len(tag)
        for kind, text in segs:
            if self._pending and self._pending[-1][0] == kind:
                self._pending[-1] = (kind, self._pending[-1][1] + text)
            else:
                self._pending.append((kind, text))

    def drain(self):
        out, self._pending = self._pending, []
        return out

    def flush(self):
        out = self._pending
        self._pending = []
        if self._tail:
            out.append(("reasoning" if self.in_think else "content", self._tail))
            self._tail = ""
        return out


def run_qoder_cosy(
    messages: list[dict],
    model: str = "Auto",
    stream: bool = True,
    max_tokens: int | None = None,
    reasoning_effort: str | None = None,
    temperature: float | None = None,
    top_p: float | None = None,
    top_k: int | None = None,
    context_length: int | None = None,
    enable_thinking: bool | None = None,
    preserve_thinking: bool | None = None,
    reasoning_budget_tokens: int | None = None,
    timeout: int = 120,
    tools: list | None = None,
    tool_choice=None,
    parallel_tool_calls: bool | None = None,
) -> Iterator[dict]:
    """
    直接 COSY API 调用，yield 事件字典：
      {"type": "content"|"reasoning", "text": str}
      {"type": "tool_calls", "delta": [...]}    # OpenAI tool_calls 增量，原样透传
      {"type": "usage", "usage": dict}
      {"type": "finish", "reason": str}

    上游 SSE 每行 data: 是 JSON 信封，body 字段是 OpenAI chunk。
    """
    # 非限免模型直接拒（付费档会真扣额度，列表里又看不到，不能凭自觉）。
    # 顺带把空 model 归一成默认限免档——上游没有 "auto"，空串更是必挂。
    # 路由层已经挡过一遍，这里是纵深防御：引擎也可能被测试/脚本直接调用。
    model = ensure_free_model(model)

    # 获取模型配置
    model_config = find_model_config(model)

    # 构建请求
    chat = {
        "messages": messages,
        "model": model,
        "stream": stream,
    }
    if max_tokens:
        chat["max_tokens"] = max_tokens
    if reasoning_effort:
        chat["reasoning_effort"] = reasoning_effort
    if tools:
        chat["tools"] = tools
    if tool_choice is not None:
        chat["tool_choice"] = tool_choice
    if parallel_tool_calls is not None:
        chat["parallel_tool_calls"] = bool(parallel_tool_calls)
    if temperature is not None:
        chat["temperature"] = temperature
    if top_p is not None:
        chat["top_p"] = top_p
    if top_k is not None:
        chat["top_k"] = top_k
    if context_length is not None:
        chat["context_length"] = context_length
    if enable_thinking is not None:
        chat["enable_thinking"] = enable_thinking
    if preserve_thinking:
        chat["preserve_thinking"] = True
    if reasoning_budget_tokens is not None:
        chat["reasoning_budget_tokens"] = reasoning_budget_tokens

    wire_body = build_request_body(chat, model_config)
    url = f"{GATEWAY_HOST}{CHAT_PATH}{CHAT_QUERY}"

    # 签名头里的 date/blob 依赖身份，重读后要重签，所以整段放在重试循环内
    for attempt in range(2):
        headers = build_cosy_headers(url, wire_body)
        if stream:
            headers["Accept"] = "text/event-stream"
            headers["Cache-Control"] = "no-cache"
        if model_config:
            headers["X-Model-Key"] = model_config.get("key", model)
            headers["X-Model-Source"] = model_config.get("source", "")

        try:
            resp = requests.post(url, headers=headers, data=wire_body, stream=stream,
                                 timeout=timeout, verify=True)
        except requests.exceptions.Timeout as e:
            raise UpstreamError(504, f"upstream timeout after {timeout}s: {e}")
        except requests.exceptions.RequestException as e:
            raise UpstreamError(502, f"upstream request failed: {e}")

        if resp.status_code in (401, 403) and attempt == 0:
            # 10605 是业务排队限流（isQueued/waitTime），换凭证没用：不续期、
            # 不在这里重发（会放大请求量），直接抛给 server 层按 waitTime 睡等重试
            if "10605" in resp.text[:500]:
                break
            reauthenticate()
            continue
        break

    if resp.status_code != 200:
        # 错误响应不是 SSE 流，可安全读取全文
        raise UpstreamError(resp.status_code, resp.text[:500])

    # 上游对这两个 path 只回 SSE，没有 JSON 单体响应形态
    splitter = _ThinkSplitter()
    for line in _iter_sse_lines(resp):
        if not line or not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if payload == "[DONE]":
            break

        try:
            envelope = json.loads(payload)
        except json.JSONDecodeError:
            continue

        # 检查错误状态
        status_code = envelope.get("statusCodeValue")
        if status_code is not None and status_code != 200:
            inner = envelope.get("body", "")
            # 10605 是业务排队限流（isQueued/waitTime），凭证没问题：不续期，
            # 直接抛给 server 层按 waitTime 睡等重试
            if not (status_code in (401, 403) and "10605" in str(inner)[:300]):
                if status_code in (401, 403):
                    reauthenticate()
            raise UpstreamError(status_code, f"上游错误: {inner[:300]}")

        # body 是 OpenAI chunk 的 JSON 字符串
        body_str = envelope.get("body", "")
        if not body_str:
            continue

        try:
            chunk = json.loads(body_str)
        except json.JSONDecodeError:
            continue

        choices = chunk.get("choices", [])
        if not choices:
            usage = chunk.get("usage")
            if usage:
                yield {"type": "usage", "usage": usage}
            continue

        choice = choices[0]
        delta = choice.get("delta", {})

        # 推理内容
        reasoning = delta.get("reasoning_content", "")
        if reasoning:
            yield {"type": "reasoning", "text": reasoning}

        # 正文内容：经 <think> 分流（上游偶发把推理模板标签内联进 content，
        # 直接透传会被客户端当正文渲染并存进会话历史）
        content = delta.get("content", "")
        if content:
            splitter.feed(content)
            for kind, text in splitter.drain():
                yield {"type": kind, "text": text}

        # tool calls：原样透传增量片段（客户端按 index 拼接 arguments）
        tool_calls = delta.get("tool_calls")
        if tool_calls:
            yield {"type": "tool_calls", "delta": tool_calls}

        finish_reason = choice.get("finish_reason")
        if finish_reason:
            yield {"type": "finish", "reason": finish_reason}

    # 流尽：冲刷跨 chunk 残留的标签前缀
    for kind, text in splitter.flush():
        if text:
            yield {"type": kind, "text": text}


# ── 测试 ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=== Qoder COSY 直接 API 测试 ===\n")

    # 加载身份
    try:
        identity = load_identity()
        print(f"身份: uid={identity['uid'][:12]}... name={identity['name']}")
        print(f"machine_id: {get_machine_id()[:12]}...")
    except Exception as e:
        print(f"身份加载失败: {e}")
        exit(1)

    # 获取模型列表
    print("\n--- 模型列表 ---")
    models = fetch_models()
    if models:
        for m in models[:10]:
            print(f"  {m['key']:25s} reasoning={m['is_reasoning']}")
    else:
        print("  (获取失败，用内置列表)")
        print(f"  {FALLBACK_MODELS}")

    # 简单推理测试
    print("\n--- 推理测试 ---")
    test_messages = [{"role": "user", "content": "说一个笑话，两句话以内"}]
    try:
        for ev in run_qoder_cosy(test_messages, model="Auto", stream=True):
            if ev["type"] == "reasoning":
                print(f"[think] {ev['text']}", end="", flush=True)
            elif ev["type"] == "content":
                print(ev["text"], end="", flush=True)
            elif ev["type"] == "tool_calls":
                print(f"\n[tool_calls] {json.dumps(ev['delta'], ensure_ascii=False)}", flush=True)
        print("\n\n✅ 推理成功")
    except Exception as e:
        print(f"\n❌ 推理失败: {e}")
