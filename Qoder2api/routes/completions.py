# -*- coding: utf-8 -*-
"""routes/completions.py — OpenAI 文本补全（legacy，/v1/completions）。

只输出正文，reasoning 不外泄。引擎 _stream/_full_completions_direct 随本路由
迁移至此；_stream_log / _openai_usage 经 core 动态查找。
"""
import json
import time
import uuid

from flask import Response, g, jsonify, request


def register(app, core):
    """挂载 completions 路由。core = server 模块（动态查找）。"""
    logger = core.logger
    qoder_cosy = core.qoder_cosy
    QODER_TIMEOUT = core.QODER_TIMEOUT
    _stream_log = core._stream_log
    _openai_usage = core._openai_usage

    def _prompt_to_text(prompt):
        """OpenAI prompt 参数：str 或 str 数组 → 纯文本"""
        if isinstance(prompt, str):
            return prompt
        if isinstance(prompt, list):
            if not prompt:
                return ""
            if all(isinstance(p, str) for p in prompt):
                return "\n".join(prompt)
            if all(isinstance(p, int) for p in prompt):
                return None  # token 数组不支持
        return None

    @app.route("/v1/completions", methods=["POST"])
    def completions():
        body = request.get_json(silent=True) or {}
        prompt_in = body.get("prompt", "")
        model_req = body.get("model", "auto")
        stream = body.get("stream", False)
        max_tokens = body.get("max_tokens")
        temperature = body.get("temperature")
        cid = f"cmpl-{uuid.uuid4().hex}"
        now = int(time.time())

        text = _prompt_to_text(prompt_in)
        if text is None:
            return jsonify({"error": {"message": "token-array prompt is not supported",
                                      "type": "invalid_request_error"}}), 400
        if not text:
            return jsonify({"error": {"message": "prompt is required",
                                      "type": "invalid_request_error"}}), 400
        messages = [{"role": "user", "content": text}]
        if stream:
            return _stream_completions_direct(messages, model_req, cid, now, temperature, max_tokens)
        return _full_completions_direct(messages, model_req, cid, now, temperature, max_tokens)

    def _stream_completions_direct(messages, model_name, cid, now, temperature=None, max_tokens=None):
        """COSY 直接 API 流式文本补全：只输出正文，reasoning 不外泄"""
        # 生成器在请求上下文销毁后才被消费，g 不可用；rid/t0 必须在此取出
        rid = g.rid
        t0 = g.t0

        def generate():
            finish_reason = None
            errored = False

            def chunk(text, fr=None):
                return {"id": cid, "object": "text_completion_chunk", "created": now, "model": model_name,
                        "choices": [{"index": 0, "text": text, "finish_reason": fr}]}

            try:
                for ev in qoder_cosy.run_qoder_cosy(
                    messages, model=model_name, stream=True, max_tokens=max_tokens,
                    timeout=QODER_TIMEOUT, temperature=temperature,
                ):
                    etype = ev["type"]
                    if etype == "finish":
                        finish_reason = ev["reason"]
                    elif etype == "content":
                        yield f"data: {json.dumps(chunk(ev['text']), ensure_ascii=False)}\n\n"
            except qoder_cosy.UpstreamError as e:
                errored = True
                logger.warning("[%s] direct completions upstream error: %s", rid, e)
                yield f"data: {json.dumps({'error': {'message': str(e), 'type': 'upstream_error', 'code': e.status}}, ensure_ascii=False)}\n\n"
            except Exception as e:
                errored = True
                logger.exception("[%s] direct completions failure", rid)
                yield f"data: {json.dumps({'error': {'message': str(e), 'type': 'api_error', 'code': 502}}, ensure_ascii=False)}\n\n"
            if not errored:
                yield f"data: {json.dumps(chunk('', finish_reason or 'stop'), ensure_ascii=False)}\n\n"
            yield "data: [DONE]\n\n"

        return Response(_stream_log(generate(), rid, t0), mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    def _full_completions_direct(messages, model_name, cid, now, temperature=None, max_tokens=None):
        """COSY 直接 API 非流式文本补全"""
        parts = []
        finish_reason = None
        usage = None
        try:
            for ev in qoder_cosy.run_qoder_cosy(
                messages, model=model_name, stream=True, max_tokens=max_tokens,
                timeout=QODER_TIMEOUT, temperature=temperature,
            ):
                etype = ev["type"]
                if etype == "content":
                    parts.append(ev["text"])
                elif etype == "usage":
                    usage = _openai_usage(ev["usage"])
                elif etype == "finish":
                    finish_reason = ev["reason"]
        except qoder_cosy.UpstreamError as e:
            logger.warning("[%s] direct completions upstream error: %s", getattr(g, "rid", "?"), e)
            return jsonify({"error": {"message": str(e), "type": "upstream_error", "code": e.status}}), e.status
        except Exception as e:
            logger.exception("[%s] direct completions failure", getattr(g, "rid", "?"))
            return jsonify({"error": {"message": str(e), "type": "api_error"}}), 502

        return jsonify({
            "id": cid, "object": "text_completion", "created": now, "model": model_name,
            "choices": [{"index": 0, "text": "".join(parts), "finish_reason": finish_reason or "stop"}],
            "usage": usage or {"prompt_tokens": None, "completion_tokens": None, "total_tokens": None},
        })
