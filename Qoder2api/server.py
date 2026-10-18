"""
server.py — Qoder2api：OpenAI 兼容的 Qoder 网关（COSY 直接 API）

端点:
  POST /v1/chat/completions   — 聊天补全 (支持 stream)
  POST /v1/completions        — 文本补全
  GET  /v1/models             — 模型列表
  GET  /health                — 健康检查
  GET  /                      — 信息面板
  GET  /login | /login/status — device flow 登录
"""
import json
import logging
import os
import re
import threading
import time
import uuid
from logging.handlers import RotatingFileHandler

from flask import Flask, Response, g, jsonify, request

from adapters import anthropic, responses
from lanes import benefit, qoder_cosy
from routes import anthropic, chat, completions, responses as routes_responses

# 兼容别名：旧探针/测试引用的旧模块名（anthropic_bridge / responses_bridge）
anthropic_bridge = anthropic
responses_bridge = responses

app = Flask(__name__)

# ── 请求日志 ───────────────────────────────────────────────────────────────────
LOG_FILE = os.path.join(os.path.dirname(__file__), "request.log")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        RotatingFileHandler(LOG_FILE, maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)
# werkzeug 访问行在响应*开始*时打（流式会误导，且与 done 行重复），禁掉
logging.getLogger("werkzeug").disabled = True

# ── 请求/响应原文落盘（默认 dumps/，DUMP_DIR 改路径，DUMP=0 关闭）─────────────
DUMP_DIR = os.environ.get("DUMP_DIR", "") or os.path.join(os.path.dirname(__file__), "dumps")
DUMP_ON = os.environ.get("DUMP", "1").strip() != "0"
DUMP_MAX_BYTES = 512 * 1024   # 单方向落盘上限，防超大响应撑爆磁盘
DUMP_MAX_FILES = int(os.environ.get("DUMP_MAX_FILES", "200"))  # ≤0 表示不轮转

_req_seq = 0
_seq_lock = threading.Lock()


def _next_req_id():
    global _req_seq
    with _seq_lock:
        _req_seq += 1
        return "r%04d" % _req_seq


def _dump_trim():
    """dump 数量超过 DUMP_MAX_FILES 时按 mtime 删最旧（明文提示词会无限增长）。"""
    if DUMP_MAX_FILES <= 0:
        return
    try:
        entries = sorted((e for e in os.scandir(DUMP_DIR) if e.is_file()),
                         key=lambda e: e.stat().st_mtime)
    except OSError:
        return
    for stale in entries[:len(entries) - DUMP_MAX_FILES]:
        try:
            os.remove(stale.path)
        except OSError:
            pass


# dump 文件名前缀启动段：rid 每进程从 r0001 重新计数，旧版同名 rid 跳重启后直接覆盖旧证据
_BOOT_TAG = time.strftime("%m%d-%H%M%S", time.localtime()) + "-p%d" % os.getpid()


def _dump_save(rid, kind, data):
    """把请求/响应原文落盘到 dumps/<req_id>.<kind>.txt（DUMP=0 时跳过）。"""
    if not DUMP_ON or not data:
        return
    try:
        os.makedirs(DUMP_DIR, exist_ok=True)
        text = data if isinstance(data, str) else data.decode("utf-8", "replace")
        truncated = len(text) > DUMP_MAX_BYTES
        path = os.path.join(DUMP_DIR, "%s.%s.%s.txt%s" % (_BOOT_TAG, rid, kind, ".truncated" if truncated else ""))
        with open(path, "w", encoding="utf-8") as f:
            f.write(text[:DUMP_MAX_BYTES])
        _dump_trim()
    except OSError as e:
        logger.warning("[%s] 落盘失败: %s", rid, e)

# ── 配置 ──────────────────────────────────────────────────────────────────────
PORT = int(os.environ.get("PORT", 8388))
API_KEY = os.environ.get("API_KEY", "")
QODER_TOKEN = os.environ.get("QODER_TOKEN", "")
QODERCN_TOKEN = os.environ.get("QODERCN_TOKEN", "")
QODER_TIMEOUT = int(os.environ.get("QODER_TIMEOUT", 120))

# 尝试从 .env 加载
def _load_dotenv():
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    if not os.path.exists(env_path):
        return
    with open(env_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip()
            if k and k not in os.environ:
                os.environ[k] = v

_load_dotenv()
PORT = int(os.environ.get("PORT", 8388))
API_KEY = os.environ.get("API_KEY", "")
QODER_TOKEN = os.environ.get("QODER_TOKEN", "")
QODERCN_TOKEN = os.environ.get("QODERCN_TOKEN", "")
QODER_TIMEOUT = int(os.environ.get("QODER_TIMEOUT", 120))


# ── 鉴权中间件 ────────────────────────────────────────────────────────────────
@app.before_request
def _check_auth():
    # rid/t0 必须在最早的 before_request 里赋值：鉴权 401 短路时 _log_request
    # 不会执行，done 行就丢了关联（且 ? 是 Windows 非法文件名）
    g.rid = _next_req_id()
    g.t0 = time.time()
    if not API_KEY:
        return  # 未设 API_KEY 则不鉴权
    if request.path in ("/", "/health", "/favicon.ico"):
        return
    auth = request.headers.get("Authorization", "")
    token = auth.replace("Bearer ", "").strip() if auth.startswith("Bearer") else ""
    if token != API_KEY:
        # 定位还在用旧 key 的客户端：记下来源与 UA
        masked = (token[:6] + "…") if token else "(empty)"
        logger.warning("[%s] 401 bad key: %s %s | ip=%s UA=%s key=%s",
                       g.rid, request.method, request.path, request.remote_addr,
                       request.headers.get("User-Agent", "-"), masked)
        return jsonify({"error": {"message": "Invalid API key", "type": "invalid_request_error"}}), 401


@app.before_request
def _log_request():
    """记录入站摘要，请求原文落盘 dumps/<rid>.req.txt（rid/t0 已在 _check_auth 赋值）"""
    if request.path in ("/", "/health", "/favicon.ico"):
        return
    body = request.get_data(as_text=True)
    summary = ""
    try:
        j = json.loads(body)
        summary = "model=%s msgs=%d tools=%d stream=%s" % (
            j.get("model"), len(j.get("messages") or []),
            len(j.get("tools") or []), j.get("stream"))
    except Exception:
        pass
    # UA 是日志里唯一的客户端归因维度（API key 全客户端共用、ip 恒为 127.0.0.1）；
    # 折掉换行防伪造多行日志
    ua = (request.headers.get("User-Agent") or "-").replace("\r", " ").replace("\n", " ")
    logger.info("[%s] in: %s %s | %s | ua=%s | body=%dB",
                g.rid, request.method, request.path, summary, ua, len(body))
    _dump_save(g.rid, "req", body)


@app.after_request
def _log_response(response):
    """非流式响应记 done（含状态码/字节/耗时）并落盘 dumps/<rid>.resp.txt；
    流式响应不能在这里读取（会整块缓冲），完成行由 _stream_log 在流末发出"""
    if request.path in ("/", "/health", "/favicon.ico"):
        return response
    if response.is_streamed:
        return response
    try:
        resp_body = response.get_data(as_text=True)
    except Exception:
        return response
    logger.info("[%s] done: status=%d %dB %.1fs",
                getattr(g, "rid", "?"), response.status_code,
                len(resp_body), time.time() - getattr(g, "t0", time.time()))
    _dump_save(getattr(g, "rid", "?"), "resp", resp_body)
    return response


def _stream_log(gen, rid, t0, ttft_skip=0):
    """包裹 SSE 生成器：TTFT、字节数、原文落盘、done/断开/中断日志。
    rid/t0 必须在请求上下文中取出后传入（生成器被消费时 g 已销毁）。
    ttft_skip：开头 N 帧不计入 TTFT。Anthropic 桥会先秒发一帧自造的开场
    message_start（不解析上游），照常停表会恒得 0.0s，故该路传 1。"""
    total = 0
    ttft = None
    seen = 0
    buf = [] if DUMP_ON else None
    try:
        for piece in gen:
            seen += 1
            if ttft is None and seen > ttft_skip:
                ttft = time.time() - t0
            total += len(piece)
            if buf is not None:
                buf.append(piece)
            yield piece
        if buf is not None:
            _dump_save(rid, "resp", "".join(buf))
        logger.info("[%s] done: stream %dB %.1fs ttft=%s",
                    rid, total, time.time() - t0,
                    ("%.1fs" % ttft) if ttft is not None else "-")
    except GeneratorExit:
        logger.warning("[%s] client 断开: stream %dB %.1fs", rid, total, time.time() - t0)
        raise
    except Exception as e:
        logger.error("[%s] 流中断: stream %dB %.1fs err=%s", rid, total, time.time() - t0, e)
        raise


# ── 未知路径/方法：回 JSON 而非 Flask 默认 HTML ────────────────────────────────
# 起因：Claude Code 把 base URL 填成 .../v1 时，请求打到 /v1/v1/messages，Flask 回
# 默认 HTML 404，客户端误报成"模型不可用/不存在"。此处统一成 JSON 错误体，且
# /messages 路用 Anthropic 形状，便于当场定位。
def _error_payload(err_type, path):
    msg = "Not Found: %s" % path
    if "/messages" in path:
        # 多半是 Anthropic 客户端 base URL 多带了 /v1，与服务端 /v1/messages 叠加
        msg += "（Anthropic 客户端 base URL 应填 host:port，不含 /v1）"
        return anthropic.error_body(err_type, msg)
    return {"error": {"message": msg, "type": err_type}}


@app.errorhandler(404)
def _not_found(e):
    return jsonify(_error_payload("not_found_error", request.path)), 404


@app.errorhandler(405)
def _method_not_allowed(e):
    return jsonify(_error_payload("invalid_request_error", request.path)), 405


# ── 模型列表 ──────────────────────────────────────────────────────────────────
@app.route("/v1/models", methods=["GET"])
def models():
    now = int(time.time())
    data = [{"id": mid, "object": "model", "created": now, "owned_by": "qoder"}
            for mid in qoder_cosy.list_model_ids()]
    return jsonify({"object": "list", "data": data})


# ── usage 映射 ────────────────────────────────────────────────────────────────
def _openai_usage(u: dict) -> dict:
    """Qoder usage → OpenAI usage"""
    out = {
        "prompt_tokens": u.get("prompt_tokens"),
        "completion_tokens": u.get("completion_tokens"),
        "total_tokens": u.get("total_tokens"),
    }
    cd = u.get("completion_tokens_details")
    if cd:
        out["completion_tokens_details"] = {"reasoning_tokens": cd.get("reasoning_tokens", 0)}
    pd = u.get("prompt_tokens_details")
    if pd:
        out["prompt_tokens_details"] = {"cached_tokens": pd.get("cached_tokens", 0)}
    return out


# ── 上游排队限流（10605）重试 ─────────────────────────────────────────────────
RATE_LIMIT_MAX_RETRIES = 2          # 最多重试次数，防长时间占住 worker
RATE_LIMIT_MAX_WAIT = 60            # waitTime 超过此值不睡等（可能真过载），直接透传错误

def _rate_limit_wait(e) -> float:
    """从 UpstreamError 里识别上游排队限流（code 10605）并取 waitTime 秒数；
    非限流错误返回 0。错误形如 HTTP 403: …{"code":"10605","message":"…waitTime\":30…"}"""
    text = str(e)
    if "10605" not in text:
        return 0.0
    try:
        wait = 30.0  # 上游文档缺省值
        for key in ("waitTime", "retryAfterSeconds"):
            m = re.search(r'"%s"\s*:\s*(\d+(?:\.\d+)?)' % key, text)
            if m:
                wait = float(m.group(1))
                break
        return wait if 0 < wait <= RATE_LIMIT_MAX_WAIT else 0.0
    except Exception:
        return 0.0


# 连接类错误：出站 TLS/TCP 建连失败（Max retries / SSLEOF / SSLError）、以及
# 流正文阶段的中断（读超时 / 连接被复位 / chunked 流断裂），与凭证、限流无关，
# 短退避重试即可。判据依赖 qoder_cosy 把这两类都包成 "upstream request failed: …"
CONNECT_RETRY_WAIT = 2.0
# 一次尝试已经耗掉这么久还不产出，多半是上游卡死而非瞬时抖动：再重发只会把 worker
# 按住几分钟（读超时是 QODER_TIMEOUT 秒）。用这个预算把慢失败限成只重试一次。
CONNECT_RETRY_MAX_ELAPSED = float(os.environ.get("QODER_CONNECT_RETRY_MAX_ELAPSED", 150))

_CONN_ERR_SIGNS = ("Max retries", "SSLEOFError", "SSLError", "ConnectionError",
                   "ConnectionReset", "Connection aborted", "Connection reset",
                   "Read timed out", "timed out", "ProtocolError", "ChunkedEncoding")


def _connect_wait(e) -> float:
    """连接类错误返回短退避秒数，其他返回 0。仅对未产出字节的请求安全。"""
    text = str(e)
    if "upstream request failed" in text and any(sig in text for sig in _CONN_ERR_SIGNS):
        return CONNECT_RETRY_WAIT
    return 0.0


def _retry_wait(e, elapsed: float = 0.0) -> float:
    """统一重试决策：限流按 waitTime 睡等，连接错误短退避，其他不重试。

    elapsed 是本次请求已经花掉的秒数，用来给「慢失败」限次：快错误（建连失败、
    秒级 TLS 中断）可以重试满 RATE_LIMIT_MAX_RETRIES；已经等满一次读超时的，
    只再给一次机会。
    """
    rate_wait = _rate_limit_wait(e)
    if rate_wait > 0:
        return rate_wait
    conn_wait = _connect_wait(e)
    if conn_wait > 0 and elapsed > CONNECT_RETRY_MAX_ELAPSED:
        return 0.0
    return conn_wait


def _chat_direct_lines(messages, model_name, cid, now, rid, t0, temperature=None, max_tokens=None,
                       top_p=None, top_k=None, context_length=None,
                       tools=None, tool_choice=None, parallel_tool_calls=None,
                       reasoning_effort=None,
                       enable_thinking=None, preserve_thinking=None,
                       reasoning_budget_tokens=None,
                       include_usage=False):
    """产出 Chat SSE 原始行（带 data: 前缀，含 [DONE] 收尾帧）。

    chat 与 responses 路由共用：后者用 responses_bridge 把这行流再包成
    Responses SSE（每帧带 sequence_number）。
    """
    finish_reason = None
    role_sent = False
    usage = None
    errored = False

    def chunk(delta, fr=None):
        return {"id": cid, "object": "chat.completion.chunk", "created": now, "model": model_name,
                "choices": [{"index": 0, "delta": delta, "finish_reason": fr}]}

    salvager = responses.InvokeSalvage() if tools else None
    tc_index = 0
    salvaged_any = False

    try:
        attempts = 0
        produced = False
        while True:
            try:
                for ev in qoder_cosy.run_qoder_cosy(
                    messages, model=model_name, stream=True, max_tokens=max_tokens, timeout=QODER_TIMEOUT,
                    tools=tools, tool_choice=tool_choice,
                    parallel_tool_calls=parallel_tool_calls,
                    reasoning_effort=reasoning_effort,
                    temperature=temperature, top_p=top_p, top_k=top_k,
                    context_length=context_length,
                    enable_thinking=enable_thinking,
                    reasoning_budget_tokens=reasoning_budget_tokens,
                    preserve_thinking=preserve_thinking,
                ):
                    produced = True
                    etype = ev["type"]
                    if etype == "finish":
                        finish_reason = ev["reason"]
                        continue
                    if etype == "usage":
                        usage = _openai_usage(ev["usage"])
                        continue
                    if etype == "content" and salvager is not None:
                        # 正文回收：模型把工具调用写成 antml 文本（<invoke>…</invoke>）时拆回
                        # 结构化 tool_calls；其余文本实时放行（有界前瞻 ≤14 字符）
                        try:
                            events = salvager.feed(ev["text"])
                        except Exception:
                            events = [("text", ev["text"])]  # 回收器异常 → 原样透传
                        first = True
                        for kind, payload in events:
                            if kind == "text" and not payload:
                                continue
                            delta = {}
                            if first and not role_sent:
                                delta["role"] = "assistant"
                                role_sent = True
                            first = False
                            if kind == "text":
                                delta["content"] = payload
                            else:
                                delta["tool_calls"] = [{
                                    "index": tc_index,
                                    "id": "call_" + uuid.uuid4().hex[:24],
                                    "type": "function",
                                    "function": {
                                        "name": payload["name"],
                                        "arguments": json.dumps(payload["params"],
                                                                 ensure_ascii=False),
                                    },
                                }]
                                tc_index += 1
                                salvaged_any = True
                                logger.info("[%s] antml回收 -> tool_call %s", rid, payload["name"])
                            yield f"data: {json.dumps(chunk(delta), ensure_ascii=False)}\n\n"
                        continue
                    delta = {}
                    if not role_sent:
                        delta["role"] = "assistant"
                        role_sent = True
                    if etype == "reasoning":
                        delta["reasoning_content"] = ev["text"]
                    elif etype == "content":
                        delta["content"] = ev["text"]
                    elif etype == "tool_calls":
                        delta["tool_calls"] = ev["delta"]
                    yield f"data: {json.dumps(chunk(delta), ensure_ascii=False)}\n\n"
                break
            except qoder_cosy.UpstreamError as e:
                # 限流（10605）按 waitTime 睡等、连接类错误短退避；
                # 均仅在尚未给客户端产出任何字节时重试，否则透传错误
                wait = _retry_wait(e, time.time() - t0)
                if produced or attempts >= RATE_LIMIT_MAX_RETRIES or wait <= 0:
                    raise
                attempts += 1
                logger.warning("[%s] 上游错误重试(%s)，%.0fs 后第 %d/%d 次",
                               rid, getattr(e, "status", "?"), wait, attempts, RATE_LIMIT_MAX_RETRIES)
                # 睡等期间向客户端发 SSE 注释行心跳（客户端忽略内容但会重置
                # 首帧超时），防止 30s 等待被 ai-sdk 之类的客户端掐断
                beat_deadline = time.time() + wait
                while time.time() < beat_deadline:
                    remain = beat_deadline - time.time()
                    time.sleep(min(5.0, max(remain, 0.1)))
                    if time.time() < beat_deadline:
                        yield ": keep-alive\n\n"
                yield ": retrying\n\n"
    except qoder_cosy.UpstreamError as e:
        errored = True
        logger.warning("[%s] direct stream upstream error: %s", rid, e)
        err = {"error": {"message": str(e), "type": "upstream_error", "code": e.status}}
        yield f"data: {json.dumps(err, ensure_ascii=False)}\n\n"
    except Exception as e:
        errored = True
        # 带上 rid：没有 rid 的堆栈无法和 in:/done: 行对上，排障只能靠猜时间
        logger.exception("[%s] direct stream failure", rid)
        err = {"error": {"message": str(e), "type": "api_error", "code": 502}}
        yield f"data: {json.dumps(err, ensure_ascii=False)}\n\n"
    if not errored:
        # 回收器残留缓冲（未闭合块退回纯文本）；本回合回收过工具调用则收尾理由
        # 必须是 tool_calls，否则客户端会当成模型已说完
        if salvager is not None:
            for kind, payload in salvager.flush():
                if kind == "text" and payload:
                    if responses._INVOKE_START in payload:
                        logger.warning("[%s] 未闭合 invoke 块降级纯文本（%d 字符）", rid, len(payload))
                    tail = {"id": cid, "object": "chat.completion.chunk", "created": now,
                            "model": model_name,
                            "choices": [{"index": 0, "delta": {"content": payload},
                                         "finish_reason": None}]}
                    yield f"data: {json.dumps(tail, ensure_ascii=False)}\n\n"
            if salvaged_any and finish_reason in (None, "stop"):
                finish_reason = "tool_calls"
        done = {"id": cid, "object": "chat.completion.chunk", "created": now, "model": model_name,
                "choices": [{"index": 0, "delta": {}, "finish_reason": finish_reason or "stop"}]}
        yield f"data: {json.dumps(done, ensure_ascii=False)}\n\n"
        if include_usage:
            usage_chunk = {"id": cid, "object": "chat.completion.chunk", "created": now,
                           "model": model_name, "choices": [], "usage": usage or {}}
            yield f"data: {json.dumps(usage_chunk, ensure_ascii=False)}\n\n"
    yield "data: [DONE]\n\n"


def _stream_chat_direct(messages, model_name, cid, now, temperature=None, max_tokens=None,
                        top_p=None, top_k=None, context_length=None,
                        tools=None, tool_choice=None, parallel_tool_calls=None,
                        reasoning_effort=None,
                        enable_thinking=None, preserve_thinking=None,
                        reasoning_budget_tokens=None,
                        include_usage=False):
    """COSY 直接 API 流式响应"""
    # 生成器在请求上下文销毁后才被消费，g 不可用；rid/t0 必须在此取出（与 _stream_log 同理）
    rid = g.rid
    t0 = g.t0
    lines = _chat_direct_lines(messages, model_name, cid, now, rid, t0,
                               temperature=temperature, max_tokens=max_tokens,
                               top_p=top_p, top_k=top_k, context_length=context_length,
                               tools=tools, tool_choice=tool_choice,
                               parallel_tool_calls=parallel_tool_calls,
                               reasoning_effort=reasoning_effort,
                               enable_thinking=enable_thinking, preserve_thinking=preserve_thinking,
                               reasoning_budget_tokens=reasoning_budget_tokens,
                               include_usage=include_usage)
    return Response(_stream_log(lines, rid, t0), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


def _full_chat_direct(messages, model_name, cid, now, max_tokens, temperature=None,
                      top_p=None, top_k=None, context_length=None,
                      tools=None, tool_choice=None, parallel_tool_calls=None,
                      reasoning_effort=None,
                      enable_thinking=None, preserve_thinking=None,
                      reasoning_budget_tokens=None):
    """COSY 直接 API 非流式响应"""
    content_parts = []
    thinking_parts = []
    tool_calls = {}
    finish_reason = None
    usage = None
    attempts = 0
    while True:
        try:
            for ev in qoder_cosy.run_qoder_cosy(
                messages, model=model_name, stream=True, max_tokens=max_tokens, timeout=QODER_TIMEOUT,
                tools=tools, tool_choice=tool_choice,
                parallel_tool_calls=parallel_tool_calls,
                reasoning_effort=reasoning_effort,
                temperature=temperature, top_p=top_p, top_k=top_k,
                context_length=context_length,
                enable_thinking=enable_thinking,
                reasoning_budget_tokens=reasoning_budget_tokens,
                preserve_thinking=preserve_thinking,
            ):
                etype = ev["type"]
                if etype == "reasoning":
                    thinking_parts.append(ev["text"])
                elif etype == "content":
                    content_parts.append(ev["text"])
                elif etype == "usage":
                    usage = _openai_usage(ev["usage"])
                elif etype == "finish":
                    finish_reason = ev["reason"]
                elif etype == "tool_calls":
                    for tc in ev["delta"]:
                        slot = tool_calls.setdefault(
                            tc.get("index", len(tool_calls)),
                            {"id": "", "type": "function", "function": {"name": "", "arguments": ""}},
                        )
                        if tc.get("id"):
                            slot["id"] = tc["id"]
                        fn = tc.get("function") or {}
                        if fn.get("name"):
                            slot["function"]["name"] += fn["name"]
                        if fn.get("arguments"):
                            slot["function"]["arguments"] += fn["arguments"]
            break
        except qoder_cosy.UpstreamError as e:
            # 非流式在聚合开始前整体重试是安全的（无半截内容）；限流按 waitTime、
            # 连接错误短退避，持续失败则透传
            wait = _retry_wait(e, time.time() - g.t0)
            if attempts >= RATE_LIMIT_MAX_RETRIES or wait <= 0:
                logger.warning("[%s] direct upstream error: %s", g.rid, e)
                return jsonify({"error": {"message": str(e), "type": "upstream_error", "code": e.status}}), e.status
            attempts += 1
            logger.warning("[%s] 上游错误重试(%s)，%.0fs 后第 %d/%d 次",
                           g.rid, getattr(e, "status", "?"), wait, attempts, RATE_LIMIT_MAX_RETRIES)
            time.sleep(wait)
        except Exception as e:
            logger.exception("[%s] upstream request failed", g.rid)
            return jsonify({"error": {"message": str(e), "type": "api_error"}}), 502

    message = {"role": "assistant", "content": "".join(content_parts)}
    if thinking_parts:
        message["reasoning_content"] = "".join(thinking_parts)
    # 非流式回收：模型把工具调用写成 antml 文本时拆回结构化 tool_calls（排在原有之后）
    if tools and message["content"]:
        try:
            salv = responses.InvokeSalvage()
            events = salv.feed(message["content"]) + salv.flush()
        except Exception:
            events = [("text", message["content"])]
        texts, calls = [], []
        for kind, payload in events:
            if kind == "text":
                texts.append(payload)
            else:
                calls.append({"id": "call_" + uuid.uuid4().hex[:24], "type": "function",
                              "function": {"name": payload["name"],
                                           "arguments": json.dumps(payload["params"],
                                                                    ensure_ascii=False)}})
        message["content"] = "".join(texts) or None
        if calls:
            logger.info("[%s] antml回收 -> tool_call %s", getattr(g, "rid", "?"),
                        [c["function"]["name"] for c in calls])
            base = max(tool_calls) + 1 if tool_calls else 0
            for i, c in enumerate(calls):
                tool_calls[base + i] = c
    if tool_calls:
        message["tool_calls"] = [tool_calls[k] for k in sorted(tool_calls)]
        finish_reason = "tool_calls"
    elif not message["content"]:
        message["content"] = None
    return jsonify({
        "id": cid, "object": "chat.completion", "created": now, "model": model_name,
        "choices": [{"index": 0, "message": message, "finish_reason": finish_reason or "stop"}],
        "usage": usage or {"prompt_tokens": None, "completion_tokens": None, "total_tokens": None},
    })


# ── 协议路由层挂载（routes/）：每协议一个文件，本文件留引擎与调度 ─────────────
# register(app, core) 里 core 传本模块：路由经模块属性动态查找引擎与重试决策
# （_chat_direct_lines / _stream_log / _retry_wait / qoder_cosy 等），测试对
# server.qoder_cosy 的打桩对路由层同样生效。
import sys as _sys

_core = _sys.modules[__name__]
chat.register(app, _core)
routes_responses.register(app, _core)
anthropic.register(app, _core)
completions.register(app, _core)


# ── 旁路路由（登录/健康/面板/签到） ───────────────────────────────────────────
import webui
webui.register_routes(app, api_key=API_KEY, port=PORT,
                      is_cn=bool(QODERCN_TOKEN) or not QODER_TOKEN)


if __name__ == "__main__":
    is_cn = bool(QODERCN_TOKEN) or not QODER_TOKEN
    # app.run 会打自己的 banner（flask.cli.show_server_banner），关掉免得插进横幅中间
    import flask.cli
    flask.cli.show_server_banner = lambda *a, **k: None

    ident, ident_err = None, ""
    try:
        ident = qoder_cosy.load_identity()
    except Exception as e:
        ident_err = type(e).__name__
    try:
        models = f"{len(qoder_cosy.list_model_ids())} 个"
    except Exception:
        models = "未知"

    print("🤖 Qoder2api 已启动")
    print(f"   本地  http://127.0.0.1:{PORT}   Base URL /v1   API Key {API_KEY or '未设（不鉴权）'}")
    print(f"   面板  http://127.0.0.1:{PORT}/")
    print(f"   区域  {'CN' if is_cn else 'INTL'}")
    print(f"   上游  gateway.qoder.com.cn")
    print(f"   身份  {ident.get('name') or '?'}（{str(ident.get('uid') or '?')[:8]}…）" if ident
          else f"   身份  无可用凭证（{ident_err}）")
    print(f"   凭证  {ident.get('source')} / {ident.get('token_type')}，落盘 credentials.json（可自续期）" if ident
          else "   凭证  —")
    print(f"   模型  {models}")

    # 启动每日签到线程
    benefit.start_daily_checkin(is_cn=is_cn, auto_open=False)
    app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)
