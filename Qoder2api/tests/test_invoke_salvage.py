# -*- coding: utf-8 -*-
"""test_invoke_salvage.py — antml 文本工具调用回收回放验证

用 r0156 的真实载荷（模型把 Bash 调用写成正文的那次）验证四条路径：
  1. InvokeSalvage 解析（7 字符跨 delta 拆块）
  2. _chat_direct_lines 流式接线（带 tools：拆回 tool_calls、finish 纠正）
  3. 不带 tools 时原样透传（不误伤）
  4. _full_chat_direct 非流式回收
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import server
from adapters import responses as rb

TAG = "parameter"


def _p(k, v):
    return "<" + TAG + ' name="' + k + '">' + v + "</" + TAG + ">"


CMD = ("cd /c/Users/12925/AppData/Local/Temp && sed -i "
       "'s|new Promise<number>(res|new Promise(res|' resident.mjs "
       "&& node resident.mjs 2>&1 | tail -14")
BLOCK = ('<invoke name="Bash">'
         + _p("command", CMD)
         + _p("description", "Fix TS annotation and rerun resident measurement")
         + _p("timeout", "600000")
         + "</invoke>")
CONTENT = "`.mjs` 里带了 TS 泛型标注，被当成构造调用了。改掉重跑：\n\n\n" + BLOCK
LEAD = "`.mjs` 里带了 TS 泛型标注，被当成构造调用了。改掉重跑：\n\n\n"


def _fake_run(events):
    def run(messages, **kw):
        for ev in events:
            yield ev
    return run


def _sse_chunks(lines):
    out = []
    for ln in lines:
        if ln.startswith("data: "):
            body = ln[6:].strip()
            out.append("[DONE]" if body == "[DONE]" else json.loads(body))
    return out


def _texts(data):
    t = ""
    for c in data:
        if isinstance(c, dict) and c.get("choices"):
            t += c["choices"][0].get("delta", {}).get("content") or ""
    return t


def _tool_calls(data):
    tcs = []
    for c in data:
        if isinstance(c, dict) and c.get("choices"):
            tcs.extend(c["choices"][0].get("delta", {}).get("tool_calls") or [])
    return tcs


def test_salvage_split_feed():
    s = rb.InvokeSalvage()
    ev = []
    for i in range(0, len(CONTENT), 7):
        ev += s.feed(CONTENT[i:i + 7])
    ev += s.flush()
    assert ev and ev[-1][0] == "tool_call", ev
    assert all(k == "text" for k, _ in ev[:-1]), ev
    assert "".join(p for k, p in ev if k == "text") == LEAD
    tc = ev[-1][1]
    assert tc["name"] == "Bash"
    assert tc["params"]["command"] == CMD
    assert tc["params"]["timeout"] == 600000 and isinstance(tc["params"]["timeout"], int)
    assert tc["params"]["description"] == "Fix TS annotation and rerun resident measurement"


def test_stream_with_tools():
    chunks = [CONTENT[i:i + 13] for i in range(0, len(CONTENT), 13)]
    server.qoder_cosy.run_qoder_cosy = _fake_run(
        [{"type": "content", "text": c} for c in chunks] + [{"type": "finish", "reason": "stop"}])
    lines = list(server._chat_direct_lines(
        [{"role": "user", "content": "hi"}], "qwen-test", "chatcmpl-replay", 1760000000,
        "r0156replay", 0.0, tools=[{"type": "function", "function": {"name": "Bash"}}],
        include_usage=True))
    data = _sse_chunks(lines)
    texts = _texts(data)
    assert "<invoke" not in texts, texts
    assert LEAD in texts
    tcs = _tool_calls(data)
    assert len(tcs) == 1, tcs
    args = json.loads(tcs[0]["function"]["arguments"])
    assert args == {"command": CMD,
                    "description": "Fix TS annotation and rerun resident measurement",
                    "timeout": 600000}, args
    frs = [c["choices"][0].get("finish_reason") for c in data
           if isinstance(c, dict) and c.get("choices") and c["choices"][0].get("finish_reason")]
    assert frs == ["tool_calls"], frs
    assert data[-1] == "[DONE]"


def test_stream_without_tools_passthrough():
    chunks = [CONTENT[i:i + 13] for i in range(0, len(CONTENT), 13)]
    server.qoder_cosy.run_qoder_cosy = _fake_run(
        [{"type": "content", "text": c} for c in chunks] + [{"type": "finish", "reason": "stop"}])
    lines = list(server._chat_direct_lines(
        [{"role": "user", "content": "hi"}], "qwen-test", "chatcmpl-replay2", 1760000000,
        "r0156replay2", 0.0))
    data = _sse_chunks(lines)
    assert CONTENT == _texts(data)  # 原样透传，一字不改


def test_full_nonstream():
    server.qoder_cosy.run_qoder_cosy = _fake_run(
        [{"type": "content", "text": CONTENT}, {"type": "finish", "reason": "stop"}])
    with server.app.app_context():
        resp = server._full_chat_direct(
            [{"role": "user", "content": "hi"}], "qwen-test", "chatcmpl-replay3",
            1760000000, 1024, tools=[{"type": "function", "function": {"name": "Bash"}}])
    body = json.loads(resp.get_data())
    msg = body["choices"][0]["message"]
    assert "<invoke" not in (msg["content"] or ""), msg
    assert msg["content"] == LEAD
    assert body["choices"][0]["finish_reason"] == "tool_calls"
    fn = msg["tool_calls"][0]["function"]
    assert fn["name"] == "Bash"
    assert json.loads(fn["arguments"])["timeout"] == 600000


if __name__ == "__main__":
    test_salvage_split_feed()
    print("1/4 salvage split-feed 真实载荷        PASS")
    test_stream_with_tools()
    print("2/4 流式接线（带 tools）回收+finish纠正 PASS")
    test_stream_without_tools_passthrough()
    print("3/4 流式无 tools 原样透传              PASS")
    test_full_nonstream()
    print("4/4 非流式回收                          PASS")
    print("ALL PASS")
