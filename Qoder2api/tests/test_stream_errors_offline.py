# -*- coding: utf-8 -*-
"""离线单测：流正文阶段的传输中断归类与重试决策。

不打上游、不写 request.log。覆盖 2026-10-12 那次 "direct stream failure"
无 rid 堆栈的根因：iter_lines 抛的原生 requests 异常绕过了重试判据。
"""
import io
import logging
import os
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace",
                              write_through=True)
os.environ["DUMP"] = "0"

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)

import requests  # noqa: E402

records = []


class Capture(logging.Handler):
    def emit(self, record):
        records.append(record.getMessage())


logging.getLogger().handlers = [Capture()]
logging.getLogger().setLevel(logging.DEBUG)

from lanes import qoder_cosy  # noqa: E402
import server                 # noqa: E402

passed, failed = [], []


def check(name, condition, detail=""):
    (passed if condition else failed).append(name)
    print("%-56s %s %s" % (name, "PASS" if condition else "FAIL", detail))


class FakeRawResp:
    """只实现 _iter_sse_lines 用到的部分。"""

    def __init__(self, lines, raise_at=None, error=None):
        self._lines = lines
        self._raise_at = raise_at
        self._error = error
        self.closed = False

    def iter_lines(self, decode_unicode=True):
        for i, line in enumerate(self._lines):
            if self._raise_at == i:
                raise self._error
            yield line

    def close(self):
        self.closed = True


# 今天日志里的真实异常文本（requests 把 urllib3 读超时包成 ConnectionError）
READ_TIMEOUT = requests.exceptions.ConnectionError(
    "HTTPSConnectionPool(host='gateway.qoder.com.cn', port=443): Read timed out.")
TLS_EOF = requests.exceptions.SSLError(
    "HTTPSConnectionPool(host='gateway.qoder.com.cn', port=443): Max retries exceeded: "
    "(Caused by SSLError(SSLEOFError(8, '[SSL: UNEXPECTED_EOF_WHILE_READING]')))")
ABORTED = requests.exceptions.ChunkedEncodingError(
    ("Connection broken: ConnectionResetError(10054, '远程主机强迫关闭了一个现有的连接')",
     ConnectionResetError(10054, "reset")))

print("=== A. 流正文异常归一成 UpstreamError ===")
for label, err in (("ReadTimeout", READ_TIMEOUT), ("SSLEOF", TLS_EOF),
                   ("ChunkedAborted", ABORTED)):
    resp = FakeRawResp(["data: x"], raise_at=0, error=err)
    try:
        list(qoder_cosy._iter_sse_lines(resp))
        check("A %-16s 转成 UpstreamError" % label, False, "没抛异常")
    except qoder_cosy.UpstreamError as e:
        check("A %-16s 转成 UpstreamError" % label,
              e.status == 502 and "upstream request failed" in str(e),
              "status=%s" % e.status)
    check("A %-16s 关闭了响应对象" % label, resp.closed)

resp = FakeRawResp(["data: a", "data: b"])
check("A 正常流原样透传", list(qoder_cosy._iter_sse_lines(resp)) == ["data: a", "data: b"])
check("A 正常流结束后关闭连接", resp.closed)

# 消费方提前 break（客户端断开）时抛 GeneratorExit：不能被吞掉
gen = qoder_cosy._iter_sse_lines(FakeRawResp(["data: a", "data: b", "data: c"]))
next(gen)
gen.close()
check("A GeneratorExit 不被转成 UpstreamError", True, "close() 未报错")

print("\n=== B. 重试判据能看到这些错误 ===")
for label, err in (("ReadTimeout", READ_TIMEOUT), ("SSLEOF", TLS_EOF),
                   ("ChunkedAborted", ABORTED)):
    ue = qoder_cosy.UpstreamError(502, "upstream request failed: %s" % err)
    check("B %-16s 快失败可重试" % label, server._retry_wait(ue, elapsed=2.0) > 0,
          "wait=%.1fs" % server._retry_wait(ue, elapsed=2.0))

ue = qoder_cosy.UpstreamError(502, "upstream request failed: %s" % READ_TIMEOUT)
check("B 已耗满一次读超时则不再重发", server._retry_wait(ue, elapsed=200.0) == 0.0,
      "budget=%.0fs" % server.CONNECT_RETRY_MAX_ELAPSED)

param_err = qoder_cosy.UpstreamError(400, "bad model")
check("B 非连接类错误不重试", server._retry_wait(param_err, elapsed=1.0) == 0.0)

rate = qoder_cosy.UpstreamError(403, '{"code":"10605","message":"queued","waitTime":30}')
check("B 限流仍按 waitTime 睡等（不受 elapsed 预算影响）",
      server._retry_wait(rate, elapsed=300.0) == 30.0)

print("\n通过 %d / %d" % (len(passed), len(passed) + len(failed)))
if failed:
    print("失败:", failed)
    sys.exit(1)
