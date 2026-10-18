# -*- coding: utf-8 -*-
"""routes/responses.py — OpenAI Responses 路由（/v1/responses）。

grok-build / Codex 等原生 Responses 客户端。上游仍是 COSY 事件流：请求体经
adapters/responses.py 转成 Chat，与 chat 共用同一事件源与 Chat SSE 行帧化
（server._chat_direct_lines），响应侧包成 Responses SSE（每帧带 sequence_number）。
"""
import json
import time
import uuid

from flask import Response, g, jsonify, request

from adapters import responses as rb


def register(app, core):
    """挂载 responses 路由。core = server 模块（动态查找，测试打桩对路由层生效）。"""
    _chat_direct_lines = core._chat_direct_lines
    _full_chat_direct = core._full_chat_direct
    _stream_log = core._stream_log

    @app.route("/v1/responses", methods=["POST"])
    def responses_api():
        body = request.get_json(silent=True)
        if not isinstance(body, dict) or not body:
            return jsonify({"error": {"message": "invalid request: JSON object body required",
                                      "type": "invalid_request_error"}}), 400

        chat_body = rb.responses_to_chat(body)
        messages = chat_body.get("messages", [])
        if not messages:
            return jsonify({"error": {"message": "invalid request: 'input' is required",
                                      "type": "invalid_request_error"}}), 400

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
            # responses 必须带 usage：强制 include_usage，让 bridge 拿到 token 数
            lines = _chat_direct_lines(messages, model_req, cid, now, rid, t0,
                                       temperature=temperature, max_tokens=max_tokens,
                                       top_p=top_p, tools=tools, tool_choice=tool_choice,
                                       parallel_tool_calls=parallel_tool_calls,
                                       include_usage=True)

            def generate():
                # Qoder 的 _stream_log 按 str 攒帧落盘（chat 路径也是 str 帧），边界解码
                for frame in rb.chat_sse_to_responses(lines, model_req):
                    yield frame.decode("utf-8")

            return Response(_stream_log(generate(), rid, t0, ttft_skip=2), mimetype="text/event-stream",
                            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

        result = _full_chat_direct(messages, model_req, cid, now, max_tokens, temperature,
                                   top_p=top_p, tools=tools, tool_choice=tool_choice,
                                   parallel_tool_calls=parallel_tool_calls)
        if result.status_code != 200:
            return result
        chat_json = json.loads(result.get_data())
        return jsonify(rb.chat_json_to_responses(chat_json, model_req))
