# -*- coding: utf-8 -*-
"""/v1/responses 路由端到端验证（Flask test_client + mock qoder_cosy 事件源）。

monkeypatch 掉 qoder_cosy.run_qoder_cosy / _openai_usage，覆盖：
  1. /v1/responses 流式：Responses SSE 合法（seq 连续、生命周期、usage、items）
  2. /v1/responses 非流式：Responses JSON 合法（复用 _full_chat_direct 聚合）
  3. /v1/chat/completions 流式回归：_chat_direct_lines 抽取不破坏老路由
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import server


def parse_frames(raw):
    events = []
    for block in raw.split(b"\n\n"):
        block = block.strip()
        if not block.startswith(b"data:"):
            continue
        payload = block[5:].decode("utf-8").strip()
        if not payload or payload == "[DONE]":
            continue
        events.append(json.loads(payload))
    return events


USAGE = {"prompt_tokens": 10, "completion_tokens": 7, "total_tokens": 17,
         "completion_tokens_details": {"reasoning_tokens": 3},
         "prompt_tokens_details": {"cached_tokens": 0}}

EVENTS = [
    {"type": "reasoning", "text": "think "},
    {"type": "reasoning", "text": "ok"},
    {"type": "content", "text": "Hi!"},
    {"type": "tool_calls", "delta": [
        {"index": 0, "id": "call_1", "type": "function",
         "function": {"name": "get_weather", "arguments": '{"city": "BJ"}'}}]},
    {"type": "finish", "reason": "tool_calls"},
    {"type": "usage", "usage": USAGE},
]

captured = {}


def install_fake():
    server.API_KEY = ""  # .env 设了 key 时会拦截测试，置空绕过（守卫逻辑：空则不鉴权）

    def fake_run(messages, **kwargs):
        captured["messages"] = messages
        captured["tools"] = kwargs.get("tools")
        for ev in EVENTS:
            yield ev

    server.qoder_cosy.run_qoder_cosy = fake_run
    server._openai_usage = lambda u: dict(u)


def main():
    install_fake()
    client = server.app.test_client()
    resp_req = {
        "model": "test-model",
        "stream": True,
        "instructions": "sys prompt",
        "input": [{"type": "message", "role": "user", "content": "hello"}],
        "tools": [{"type": "function", "name": "get_weather", "description": "w",
                   "parameters": {"type": "object",
                                  "properties": {"city": {"type": "string"}}}}],
    }

    # ---------- 1) /v1/responses 流式 ----------
    r = client.post("/v1/responses", json=resp_req)
    assert r.status_code == 200, (r.status_code, r.data[:500])
    assert "text/event-stream" in r.headers.get("Content-Type", "")
    # COSY 事件源是懒调用（生成器内才发起），必须先消费流 captured 才有值
    raw = r.data

    # 请求侧：到上游的应该是 Chat 格式
    assert captured["messages"][0] == {"role": "system", "content": "sys prompt"}
    assert captured["messages"][1] == {"role": "user", "content": "hello"}
    assert captured["tools"][0]["function"]["name"] == "get_weather"

    events = parse_frames(r.data)
    seqs = [e["sequence_number"] for e in events]
    assert seqs == list(range(len(events))), seqs
    types = [e["type"] for e in events]
    print("responses 流事件序列（%d 帧）:" % len(events))
    for i, e in enumerate(events):
        print("  %2d %s" % (i, e["type"]))
    assert types[0] == "response.created"
    assert types[1] == "response.in_progress"
    assert types[-1] == "response.completed"
    final = events[-1]["response"]
    for k in ("id", "object", "created_at", "model", "status", "output"):
        assert k in final, k
    assert final["status"] == "completed"
    assert [o["type"] for o in final["output"]] == \
        ["reasoning", "message", "function_call"], final["output"]
    assert final["usage"]["total_tokens"] == 17
    fn = final["output"][2]
    assert fn["call_id"] == "call_1" and fn["arguments"] == '{"city": "BJ"}'

    # ---------- 2) /v1/responses 非流式 ----------
    r = client.post("/v1/responses", json=dict(resp_req, stream=False))
    assert r.status_code == 200, (r.status_code, r.data[:500])
    out = r.get_json()
    assert out["object"] == "response" and out["status"] == "completed"
    assert [o["type"] for o in out["output"]] == \
        ["reasoning", "message", "function_call"], out["output"]
    assert out["usage"]["total_tokens"] == 17

    # ---------- 3) /v1/chat/completions 回归 ----------
    r = client.post("/v1/chat/completions",
                    json={"model": "test-model", "stream": True,
                          "stream_options": {"include_usage": True},
                          "messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 200, (r.status_code, r.data[:300])
    assert b"data: " in r.data and b"[DONE]" in r.data
    chunks = parse_frames(r.data)
    assert any("tool_calls" in json.dumps(c) for c in chunks)

    print("ALL PASS")


if __name__ == "__main__":
    main()
