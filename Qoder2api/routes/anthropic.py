# -*- coding: utf-8 -*-
"""routes/anthropic.py — Anthropic Messages 路由（/v1/messages）。

与 /v1/responses 同构：adapters/anthropic.py 把 Anthropic ⇄ Chat 翻掉，复用
qoder_cosy 直连；响应侧包成 Anthropic SSE。
"""
import json
import time
import uuid

from flask import Response, g, jsonify, request

from adapters import anthropic as ab


def register(app, core):
    """挂载 messages 路由。core = server 模块（动态查找，测试打桩对路由层生效）。"""
    _chat_direct_lines = core._chat_direct_lines
    _full_chat_direct = core._full_chat_direct
    _stream_log = core._stream_log

    @app.route("/v1/messages", methods=["POST"])
    def messages_api():
        body = request.get_json(silent=True)
        if not isinstance(body, dict) or not body:
            return jsonify(ab.error_body("invalid_request_error",
                "invalid request: JSON object body required")), 400

        chat_body = ab.anthropic_to_chat(body)
        messages = chat_body.get("messages", [])
        if not messages:
            return jsonify(ab.error_body("invalid_request_error",
                "invalid request: 'messages' is required")), 400

        model_req = body.get("model") or ""
        stream = bool(body.get("stream"))
        max_tokens = chat_body.get("max_tokens")
        temperature = chat_body.get("temperature")
        top_p = chat_body.get("top_p")
        tools = chat_body.get("tools")
        tool_choice = chat_body.get("tool_choice")
        parallel_tool_calls = chat_body.get("parallel_tool_calls")
        cid = "chatcmpl-" + uuid.uuid4().hex
        now = int(time.time())
        rid, t0 = g.rid, g.t0

        # 模型门禁前置：流式一旦开始产出就改不了 HTTP 状态码了，只能塞 SSE error。
        # 在这里挡，客户端才能拿到真正的 400（SDK 才会正确归类为请求错误）。
        # 必须用 ab.error_body()：Anthropic 的错误体是 {"type":"error","error":{...}}，
        # 直接给 {"error":{...}} 会让 Anthropic SDK 解析失败（它按 type 字段判形）。
        try:
            # 返回值是归一化后的模型名（省略 model 时会给默认限免档）
            model_req = core.qoder_cosy.ensure_free_model(model_req)
        except core.qoder_cosy.UpstreamError as e:
            return jsonify(ab.error_body("invalid_request_error",
                                         getattr(e, "message", str(e)))), 400

        if stream:
            lines = _chat_direct_lines(messages, model_req, cid, now, rid, t0,
                                       temperature=temperature, max_tokens=max_tokens,
                                       top_p=top_p, tools=tools, tool_choice=tool_choice,
                                       parallel_tool_calls=parallel_tool_calls,
                                       include_usage=True)

            def generate():
                for frame in ab.chat_sse_to_anthropic(lines, model_req):
                    yield frame.decode("utf-8")

            return Response(_stream_log(generate(), rid, t0, ttft_skip=1), mimetype="text/event-stream",
                            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

        result = _full_chat_direct(messages, model_req, cid, now, max_tokens, temperature,
                                   top_p=top_p, tools=tools, tool_choice=tool_choice,
                                   parallel_tool_calls=parallel_tool_calls)
        if result.status_code != 200:
            return result
        chat_json = json.loads(result.get_data())
        return jsonify(ab.chat_json_to_anthropic(chat_json, model_req))
