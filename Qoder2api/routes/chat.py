# -*- coding: utf-8 -*-
"""routes/chat.py — OpenAI Chat Completions 路由（/v1/chat/completions）。

COSY 引擎与重试决策（_chat_direct_lines / _stream_chat_direct / _full_chat_direct /
_openai_usage / _retry_wait / _stream_log）都在 server.py，本文件只做参数解包与
分发。core = server 模块动态查找，测试对 server.qoder_cosy 的打桩对路由层同样生效。
"""
import time
import uuid

from flask import g, jsonify, request


def register(app, core):
    """挂载 chat 路由。core = server 模块（动态查找，见文件头注）。"""
    logger = core.logger
    _stream_chat_direct = core._stream_chat_direct
    _full_chat_direct = core._full_chat_direct

    @app.route("/v1/chat/completions", methods=["POST"])
    def chat_completions():
        body = request.get_json(silent=True) or {}
        messages = body.get("messages", [])
        model_req = body.get("model") or ""
        stream = body.get("stream", False)
        max_tokens = body.get("max_tokens")
        temperature = body.get("temperature")
        top_p = body.get("top_p")
        top_k = body.get("top_k")
        context_length = body.get("context_length")
        tools = body.get("tools") or None
        tool_choice = body.get("tool_choice")
        parallel_tool_calls = body.get("parallel_tool_calls")
        reasoning_effort = body.get("reasoning_effort")
        enable_thinking = body.get("enable_thinking")  # 客户端显式开关思考（false 时省掉 reasoning token）
        preserve_thinking = body.get("preserve_thinking")
        reasoning_budget_tokens = body.get("reasoning_budget_tokens")
        include_usage = bool((body.get("stream_options") or {}).get("include_usage"))

        if not messages:
            return jsonify({"error": {"message": "messages is required", "type": "invalid_request_error"}}), 400

        # 模型门禁放在这里而不是只靠引擎内部：流式一旦开始产出，HTTP 状态码
        # 就改不了了，只能塞一条 SSE error 事件——客户端拿到的不是 400，
        # 很多 SDK 会当网络故障重试。在路由层先挡，两种情况都能拿到真 400。
        try:
            # 返回值是归一化后的模型名（省略 model 时会给默认限免档）
            model_req = core.qoder_cosy.ensure_free_model(model_req)
        except core.qoder_cosy.UpstreamError as e:
            return jsonify({"error": {"message": getattr(e, "message", str(e)), "type": "invalid_request_error",
                                      "code": "model_not_allowed"}}), 400

        if isinstance(tool_choice, str) and tool_choice not in ("auto", "none", "required"):
            logger.warning("[%s] tool_choice=%r 非 OpenAI 取值，不送上游",
                           getattr(g, "rid", "?"), tool_choice)

        cid = f"chatcmpl-{uuid.uuid4().hex}"
        now = int(time.time())

        if stream:
            return _stream_chat_direct(messages, model_req, cid, now, temperature, max_tokens,
                                       top_p=top_p, top_k=top_k, context_length=context_length,
                                       tools=tools, tool_choice=tool_choice,
                                       parallel_tool_calls=parallel_tool_calls,
                                       reasoning_effort=reasoning_effort,
                                       enable_thinking=enable_thinking,
                                       reasoning_budget_tokens=reasoning_budget_tokens,
                                       preserve_thinking=preserve_thinking,
                                       include_usage=include_usage)
        return _full_chat_direct(messages, model_req, cid, now, max_tokens, temperature,
                                 top_p=top_p, top_k=top_k, context_length=context_length,
                                 tools=tools, tool_choice=tool_choice,
                                 parallel_tool_calls=parallel_tool_calls,
                                 reasoning_effort=reasoning_effort,
                                 enable_thinking=enable_thinking,
                                 reasoning_budget_tokens=reasoning_budget_tokens,
                                 preserve_thinking=preserve_thinking)
