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

        model_req = body.get("model", "auto")
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
