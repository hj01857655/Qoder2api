"""
benefit.py — Qoder 每日签到 / 用量查询（全自动，无需浏览器）

签到流程：
1. 查 campaign 状态 (GET /sash/api/v1/me/campaigns, 需 Cosy-ClientType:10 头)
2. 找 claimStatus=CLAIMABLE 且 actionType=CLAIM_BENEFIT 的活动
3. POST /sash/api/v1/me/campaigns/{campaignId}/claim 直接领取
4. 按活动对象里的 endAt（本轮截止）排下一次检查；没到截止前不重复打接口
"""
# 作为独立入口（python lanes/benefit.py）运行时仓库根不在 sys.path 上，
# 兜底把仓库根加进来，否则 `from lanes import qoder_cosy` 失败。
import os as _os
import sys as _sys

_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)

import os
import json
import socket
import threading
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests

from lanes import qoder_cosy  # noqa: E402

# CN 时区 UTC+8
CN_TZ = timezone(timedelta(hours=8))

# API 配置
API_BASE_CN = "https://openapi.qoder.com.cn"
API_BASE_INTL = "https://openapi.qoder.com"
CAMPAIGNS_PATH = "/sash/api/v1/me/campaigns"
USAGE_PATH = "/sash/api/v2/me/usage"

# 签到检查间隔 (秒)
CHECK_INTERVAL = 3600

# 签到日志。之前只有 print 到 stdout：网关在后台起时控制台看不见，于是这条链上
# 任何一次成功或失败都不留痕迹 —— "到底签没签"根本无从查证。落一份文件。
LOG_FILE = Path(__file__).with_name("benefit.log")


def _log(msg: str, flush: bool = True) -> None:
    """既打到 stdout（前台跑看得见），也追加进 benefit.log。

    写日志失败绝不往上抛：磁盘满或文件被占用都不该让签到线程死掉。
    """
    print(msg, flush=flush)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{datetime.now(CN_TZ).strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
    except OSError:
        pass

# 活动轮次开放时刻 (UTC+8)：每日 Credits 与兑换码都在这一时刻开新轮
# （实测 2026-10-12：CREDITS 活动 startAt=10-12 10:00、endAt=10-13 09:59）。
# 注意：只有奶茶抢领会到点才抢；每日签到不看这个时刻，而是听服务端
# 的 startAt/endAt，因为 00:00-10:00 仍可领上一轮（错过不补、不累计）。
CLAIM_OPEN_HOUR = 10

# 奶茶免单卡活动 ID (从 app 日志获取)
COFFEE_CAMPAIGN_ID = "01a0e886-e3b4-7ab6-887c-431f37021ffa"


def _headers(token: str) -> dict:
    """campaigns 投放按头组合路由，两条实测约束（2026-10-12）：
    1. `Cosy-ClientType: 10` 必带，缺了服务端 showCampaign=false 且活动列表为空。
    2. **不能带 `Cosy-MachineToken`**：该头被当成风控指纹，值非真机
       （runtime-info.exe 生成的）时，每日 `CREDITS` 活动直接从 campaigns 响应里消失
       （claimable=false），签到线程因此永远无可领项、Add-on 不增长。只带
       MachineId 或只带 MachineType 均不影响投放，故这里保留二者、丢弃 Token。
    旧实现对齐 magpie internal/qoder/cosy.go:175-178 用 machine_id 冒充 Token，
    推理侧仍可用那套头，但活动/签到侧不行。"""
    try:
        mid = qoder_cosy.load_identity().get("machine_id") or ""
    except Exception:  # noqa: BLE001 — 无凭证时也要能构造头（请求会因无 Authorization 被拒）
        mid = ""
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "Qoder",
        "Cosy-ClientType": "10",
        "Cosy-Version": "0.4.3",
        "Cosy-MachineOS": "win32",
        "Cosy-MachineId": mid,
        "Cosy-MachineType": "5",
        "Cosy-MachineHostname": socket.gethostname(),
    }


def _get_token() -> str | None:
    """自有凭证（credentials.json，device flow 落盘）的 dt- 设备令牌；无凭证返回 None。"""
    try:
        return qoder_cosy.load_identity().get("access_token")
    except Exception as e:  # noqa: BLE001 — 无凭证时降级为错误返回，不抛
        _log(f"[benefit] 凭证不可用: {type(e).__name__}", flush=True)
        return None


# ── 结论码 / 传输重试 ────────────────────────────────────────
# check_and_claim 的结论。签到线程只对 DEFINITIVE_REASONS 记账（当天不再重试），
# 其余一律留到下一轮 —— 否则一次网络抖动就能静默漏掉一整天的 100 Credits。
REASON_CLAIMED = "CLAIMED"                  # 本轮领到了
REASON_ALREADY = "ALREADY_CLAIMED_TODAY"    # 服务端回显：这一轮已领过
REASON_NOT_DELIVERED = "NOT_DELIVERED"      # 列表里没有 CREDITS 活动（账号不匹配或被风控隐藏）
REASON_QUERY_FAILED = "QUERY_FAILED"        # 活动列表没查到（HTTP 非 200 / 重试耗尽）
REASON_CLAIM_FAILED = "CLAIM_FAILED"        # 查到可领但领取失败
DEFINITIVE_REASONS = (REASON_CLAIMED, REASON_ALREADY)

# openapi.qoder.com.cn 偶发 TLS 握手中断（实测 2026-10-12：约 7 次请求里 2 次
# SSLEOFError），一次失败不代表业务结果，必须退避重试后再下结论。
TRANSIENT_EXC = (requests.exceptions.SSLError,
                 requests.exceptions.ConnectionError,
                 requests.exceptions.Timeout)


def _request(method: str, url: str, headers: dict, timeout: int = 15,
             tries: int = 4, backoff: float = 1.5):
    """带退避重试的 requests；耗尽后抛最后一次异常，由调用方折算成 QUERY_FAILED。"""
    last = None
    for i in range(tries):
        try:
            return requests.request(method, url, headers=headers, timeout=timeout)
        except TRANSIENT_EXC as e:
            last = e
            if i < tries - 1:
                time.sleep(backoff * (i + 1))
    raise last


def _benefit_kind(c: dict) -> str | None:
    return (c.get("benefit") or {}).get("kind")


def _brief(c: dict) -> str:
    """一行摘要；签到日志用它说明服务端到底投了哪些活动、各自什么状态。"""
    b = c.get("benefit") or {}
    return (f"{c.get('campaignKey')} kind={b.get('kind')} "
            f"amount={b.get('amount')} status={c.get('claimStatus')}")


def get_usage() -> dict:
    """查用量 (GET /sash/api/v2/me/usage)，瞬时抖动自动重试"""
    token = _get_token()
    if not token:
        return {"error": "no credential (run: python oauth.py)"}
    base = API_BASE_CN  # 本仓库只接 Qoder CN
    try:
        r = _request("GET", f"{base}{USAGE_PATH}", _headers(token))
        if r.status_code == 200:
            return r.json()
        return {"error": f"HTTP {r.status_code}", "body": r.text[:500]}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


def check_campaigns(is_cn: bool = True) -> dict:
    """查活动状态，返回 {showCampaign, claimable, campaigns, claimable_campaigns}。

    带 `error` 表示「没拿到可信结果」（重试耗尽或 HTTP 非 200），和「确实没有可领
    活动」是两回事 —— 调用方必须区分，否则一次抖动就会被当成今日已签到。"""
    token = _get_token()
    if not token:
        return {"error": "no credential (run: python oauth.py)", "claimable": False, "campaigns": []}
    base = API_BASE_CN if is_cn else API_BASE_INTL
    try:
        r = _request("GET", f"{base}{CAMPAIGNS_PATH}", _headers(token))
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}", "claimable": False, "campaigns": []}
        data = r.json()
        # 领所有 CLAIMABLE 活动（100 Credits + 奶茶免单卡等）
        claimable_campaigns = [
            c for c in data.get("campaigns", [])
            if c.get("claimStatus") == "CLAIMABLE"
        ]
        return {
            "showCampaign": data.get("showCampaign", False),
            "claimable": bool(claimable_campaigns),
            "campaigns": data.get("campaigns", []),
            "claimable_campaigns": claimable_campaigns,
        }
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}", "claimable": False, "campaigns": []}


def claim_campaign(campaign_id: str, is_cn: bool = True) -> dict:
    """领取活动奖励 (POST /sash/api/v1/me/campaigns/{campaignId}/claim)

    成功判定只看 `status == "CLAIMED"`；`replayed` 是服务端幂等回显（此前已领），
    不算新发放。兑换码类活动也用这个函数，所以日志不写死 Credits。"""
    token = _get_token()
    if not token:
        return {"error": "no credential (run: python oauth.py)", "status": "FAILED"}
    base = API_BASE_CN if is_cn else API_BASE_INTL
    url = f"{base}{CAMPAIGNS_PATH}/{campaign_id}/claim"
    try:
        r = _request("POST", url, _headers(token))
        if r.status_code == 200:
            data = r.json()
            b = data.get("benefit") or {}
            tag = "幂等回显（此前已领）" if data.get("replayed") else "新发放"
            if data.get("status") == "CLAIMED":
                _log(f"[benefit] ✅ 领取成功 {b.get('kind')} x{b.get('amount')}（{tag}）"
                      f" campaign={data.get('campaignKey') or campaign_id}", flush=True)
            else:
                _log(f"[benefit] ❌ 领取未成功: "
                      f"{data.get('failureCode') or data.get('status')}（{tag}）", flush=True)
            return data
        _log(f"[benefit] ❌ 领取失败: HTTP {r.status_code} {r.text[:200]}", flush=True)
        return {"error": f"HTTP {r.status_code}", "body": r.text[:500], "status": "FAILED"}
    except Exception as e:
        _log(f"[benefit] ❌ 领取异常: {type(e).__name__}: {e}", flush=True)
        return {"error": f"{type(e).__name__}: {e}", "status": "FAILED"}


def check_and_claim(is_cn: bool = True, auto_open: bool = True) -> dict:
    """检查并自动签到（全自动，无需浏览器）。返回带 `reason` 的结论，供线程
    决定是否把今天记账；auto_open 保留兼容性但不再打开浏览器。"""
    now_cn = datetime.now(CN_TZ)
    result = {
        "time": now_cn.isoformat(),
        "claimable": False,
        "claimed": False,
        "campaigns": [],
        "claim_results": [],
        "reason": None,
    }

    # 不按本地钟点拦截：服务端已经按轮次发了 startAt/endAt，00:00-09:59 依旧可能
    # 有一个未领的上一轮（官方规则：错过不补领、不累计），这里只看 claimStatus。
    status = check_campaigns(is_cn=is_cn)
    if "error" in status:
        result["error"] = status["error"]
        result["reason"] = REASON_QUERY_FAILED
        _log(f"[benefit] 活动列表查询失败（{status['error']}），本轮不记账，下一轮重试", flush=True)
        return result

    result["claimable"] = status["claimable"]
    result["campaigns"] = [
        {
            "campaignId": c.get("campaignId", ""),
            "campaignKey": c.get("campaignKey", ""),
            "claimStatus": c.get("claimStatus", ""),
            "actionType": c.get("actionType", ""),
            "benefit": c.get("benefit", {}),
            "startAt": c.get("startAt"),
            "endAt": c.get("endAt"),
        }
        for c in status.get("campaigns", [])
    ]

    if not status["claimable"]:
        # 旧日志把「今日已签 / 活动未开放 / 被风控隐藏」压成一句话，看不出成因，
        # 这里按 benefit.kind 到底有没有投放来区分，并把服务端返回的列表摘要打出来
        delivered = [_benefit_kind(c) == "CREDITS" for c in status.get("campaigns", [])]
        result["reason"] = REASON_ALREADY if any(delivered) else REASON_NOT_DELIVERED
        _log(f"[benefit] 无可领活动（{result['reason']}），服务端投放: "
              f"{[_brief(c) for c in status.get('campaigns', [])]}", flush=True)
        return result

    skipped = failed = 0
    for c in status["claimable_campaigns"]:
        cid = c["campaignId"]
        if _benefit_kind(c) == "REDEMPTION_CODE" and _coffee_claimed(cid):
            _log(f"[benefit] {c.get('campaignKey')} 本地标记已领过，跳过 claim", flush=True)
            skipped += 1
            continue
        claim_result = claim_campaign(cid, is_cn=is_cn)
        result["claim_results"].append(claim_result)
        if claim_result.get("status") == "CLAIMED":
            result["claimed"] = True
            if _benefit_kind(c) == "REDEMPTION_CODE":
                # 兑换码每人限领一次，按 campaignId 落标，重启后不重复扰服务端
                _mark_coffee_claimed(cid)
        else:
            failed += 1

    if result["claimed"]:
        result["reason"] = REASON_CLAIMED
    elif skipped and not failed:
        result["reason"] = REASON_ALREADY
    else:
        result["reason"] = REASON_CLAIM_FAILED
    return result


def _round_end(result: dict):
    """本轮（CREDITS 活动）的截止时刻 + 1 分钟，即下一轮开放瞬间；取不到返回 None。
    服务端给的是 UTC 秒（实测 endAt 落在 09:59，+1min 正好 10:00:00）。"""
    for c in result.get("campaigns", []):
        if (c.get("benefit") or {}).get("kind") == "CREDITS" and c.get("endAt"):
            return datetime.fromtimestamp(c["endAt"], CN_TZ) + timedelta(minutes=1)
    return None


def _sleep_delay(next_check: datetime, now_cn: datetime) -> float:
    """签到线程本次该睡多久：距下次检查不足一小时时精确落到点（新一轮 10:00:00 开放
    就能当场抢到），更远时每小时醒一次 —— 避免 23 小时长睡遇上改点/休眠就偏移。"""
    return max(1.0, min((next_check - now_cn).total_seconds(), CHECK_INTERVAL))


def _daily_check_loop(is_cn: bool = True, auto_open: bool = True):
    """签到线程主循环：按服务端的轮次窗口排期，不按自然日、也不卡 10:00 钟点。

    只有拿到确定性结论（领到了 / 服务端确认已领）才推迟到本轮 `endAt` 之后；
    查询失败、领取失败、活动未投放都按 CHECK_INTERVAL 重试 —— 旧实现把这三类也
    当“已签”，还只在 10:00 后动手，加上头风控，就是“积分长期不涨还没人报错”的成因。"""
    next_check = datetime.now(CN_TZ)   # 到点才打接口；初值 = 启动就查一次
    while True:
        now_cn = datetime.now(CN_TZ)
        try:
            if next_check <= now_cn:
                _log(f"[benefit] 签到检查 ({now_cn.strftime('%Y-%m-%d %H:%M')} UTC+8)", flush=True)
                result = check_and_claim(is_cn=is_cn, auto_open=auto_open)
                reason = result.get("reason")
                if reason in DEFINITIVE_REASONS:
                    next_check = _round_end(result) or (now_cn + timedelta(seconds=CHECK_INTERVAL))
                    _log(f"[benefit] 本轮已了结（{reason}），下一轮 {next_check.strftime('%m-%d %H:%M:%S')} UTC+8 再查", flush=True)
                else:
                    # NOT_DELIVERED / 查询或领取失败：活动可能晚点才投放，每小时重试
                    next_check = now_cn + timedelta(seconds=CHECK_INTERVAL)
                    _log(f"[benefit] 本轮不记账（{reason}），稍后重试", flush=True)
            delay = _sleep_delay(next_check, datetime.now(CN_TZ))
        except Exception as e:
            _log(f"[benefit] 签到检查异常: {e}", flush=True)
            next_check = datetime.now(CN_TZ) + timedelta(seconds=CHECK_INTERVAL)
            delay = CHECK_INTERVAL

        time.sleep(delay)


def start_daily_checkin(is_cn: bool = True, auto_open: bool = True):
    """启动每日签到线程 + 奶茶抢领线程 (daemon)"""
    token = _get_token()
    if not token:
        _log(f"[benefit] ⚠️ 无自有凭证，签到线程不启动 (先运行: python oauth.py)", flush=True)
        return None
    t = threading.Thread(target=_daily_check_loop, args=(is_cn, auto_open), daemon=True)
    t.start()
    _log(f"[benefit] 每日签到线程已启动 (CN={is_cn}, 全自动 API 签到)", flush=True)

    # 奶茶免单卡抢领线程
    t2 = threading.Thread(target=_coffee_claim_loop, args=(is_cn,), daemon=True)
    t2.start()
    _log(f"[benefit] 🧋 奶茶抢领线程已启动 (每天 10:00:00 UTC+8 精准抢领)", flush=True)
    return t


def claim_now(is_cn: bool = True) -> dict:
    """立即签到一次"""
    return check_and_claim(is_cn=is_cn, auto_open=False)


# ── 奶茶免单卡抢领 ──────────────────────────────────────────

# 抢领窗口：10:00:00 起快速重试
COFFEE_RETRY_INTERVAL = 0.1   # 100ms
COFFEE_RETRY_DURATION = 30    # 持续 30 秒

# 领取标记（活动每人限领一次）：落盘防重启后重复打 claim。
# 按 campaignId 记录 —— 活会轮换 campaignId（每日 Credits 已从 act-20260930-736
# 换到 act-20261009-057），旧的单布尔标记会领过一次后永久收工。
_CLAIM_MARK_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".coffee_claimed")


def _read_coffee_marks() -> dict:
    """{campaignId: 领取时间}。兼容旧格式（文件里是裸 ISO 时间戳 → 归到当时写死的
    COFFEE_CAMPAIGN_ID 上），换格式不会把已有的“已领”状态弄丢。"""
    try:
        with open(_CLAIM_MARK_FILE, encoding="utf-8") as f:
            raw = f.read().strip()
    except OSError:
        return {}
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except ValueError:
        data = None
    if isinstance(data, dict):
        return data
    return {COFFEE_CAMPAIGN_ID: raw}


def _coffee_claimed(campaign_id: str | None = None) -> bool:
    marks = _read_coffee_marks()
    if campaign_id is None:
        return bool(marks)
    return campaign_id in marks


def _mark_coffee_claimed(campaign_id: str):
    marks = _read_coffee_marks()
    marks[campaign_id] = datetime.now(CN_TZ).isoformat()
    try:
        with open(_CLAIM_MARK_FILE, "w", encoding="utf-8") as f:
            f.write(json.dumps(marks, ensure_ascii=False))
    except OSError:
        pass


def _resolve_coffee_target(is_cn: bool = True) -> str | None:
    """本轮该抢的兑换码活动 campaignId；没有可抢的返回 None。

    campaignId 随活动轮换，不再依赖日志里抄的 COFFEE_CAMPAIGN_ID；列表里没出现时
    （旧取证：非完整机器指纹会被隐藏）才回退到这个旧 ID 试一次，服务端会幂等回显。"""
    status = check_campaigns(is_cn=is_cn)
    codes = [c for c in status.get("campaigns", []) if _benefit_kind(c) == "REDEMPTION_CODE"]
    if not codes:
        if status.get("error"):
            _log(f"[benefit] 奶茶：活动列表查询失败（{status['error']}），按旧 ID 试一轮", flush=True)
        return None if _coffee_claimed(COFFEE_CAMPAIGN_ID) else COFFEE_CAMPAIGN_ID
    for c in codes:
        if c.get("claimStatus") == "CLAIMABLE" and not _coffee_claimed(c["campaignId"]):
            return c["campaignId"]
    return None


def claim_coffee_card(is_cn: bool = True, campaign_id: str | None = None) -> dict:
    """抢领兑换码活动，100ms 间隔重试 30 秒；已领过（本地标记或服务端幂等回显）不再发 claim"""
    cid = campaign_id or _resolve_coffee_target(is_cn=is_cn)
    if not cid:
        _log("[benefit] 奶茶：本轮无可抢的兑换码活动（已领过或服务端未投放）", flush=True)
        return {"status": "SKIPPED", "reason": "no_claimable_redemption_code"}
    if _coffee_claimed(cid):
        _log(f"[benefit] 奶茶免单卡 {cid} 已领取过（本地标记），跳过抢领", flush=True)
        return {"status": "ALREADY_CLAIMED", "campaignId": cid}
    token = _get_token()
    if not token:
        return {"error": "no credential (run: python oauth.py)", "status": "FAILED"}
    base = API_BASE_CN if is_cn else API_BASE_INTL
    headers = _headers(token)
    url = f"{base}{CAMPAIGNS_PATH}/{cid}/claim"

    deadline = time.time() + COFFEE_RETRY_DURATION
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        try:
            r = requests.post(url, headers=headers, timeout=5)
            if r.status_code == 200:
                data = r.json()
                if data.get("status") != "FAILED":
                    # 每人限领一次：CLAIMED 即终态（replayed=true 表示此前已领，同样落标记）
                    _mark_coffee_claimed(cid)
                    tag = "幂等回显（此前已领）" if data.get("replayed") else f"第 {attempt} 次"
                    _log(f"[benefit] 🧋 奶茶免单卡领取成功 ({tag})", flush=True)
                    return data
                # FAILED but 200 — 可能是 OUT_OF_STOCK，继续重试
                failure = data.get("failureCode", "")
                if attempt <= 3 or attempt % 10 == 0:
                    _log(f"[benefit] 奶茶抢领第 {attempt} 次: {failure}", flush=True)
                if failure != "REDEMPTION_CODE_OUT_OF_STOCK":
                    if failure == "SAME_PERSON_DEPENDENCY_UNAVAILABLE":
                        # 风控要真机指纹（runtime-info.exe）；本仓库的头故意不带
                        # Cosy-MachineToken（带了会反过来隐藏每日 Credits），重试无意义
                        _log("[benefit] 🧋 风控要求真机机器指纹，当前头组合无法满足，停止抢领", flush=True)
                    return data
            elif r.status_code == 429:
                _log(f"[benefit] 奶茶抢领被限流，等待 1s", flush=True)
                time.sleep(1)
            else:
                _log(f"[benefit] 奶茶抢领 HTTP {r.status_code}: {r.text[:200]}", flush=True)
        except Exception as e:
            if attempt <= 3:
                _log(f"[benefit] 奶茶抢领异常: {e}", flush=True)
        time.sleep(COFFEE_RETRY_INTERVAL)

    _log(f"[benefit] 奶茶抢领结束，共尝试 {attempt} 次未成功", flush=True)
    return {"status": "FAILED", "failureCode": "RETRY_EXHAUSTED", "attempts": attempt}


def _coffee_claim_loop(is_cn: bool = True):
    """奶茶抢领线程：每天 10:00:00 (UTC+8) 那一轮抢。修了两处旧行为：
    1. 领过一次就 `return`（单布尔标记）→ 现在按 campaignId 记账，轮换出新一轮仍会抢。
    2. 10:00 之前启动时，走到第一个 10:00 边界会被当成“已过开放点”而跳过，
       启动当天的那一轮永远抢不到 → 现在用「线程启动时刻是否晚于今天 10:00」判定。
    """
    started = datetime.now(CN_TZ)
    burst_dates = set()
    while True:
        try:
            now_cn = datetime.now(CN_TZ)
            today = now_cn.date()

            if today in burst_dates:
                time.sleep(60)
                continue

            target = datetime(now_cn.year, now_cn.month, now_cn.day,
                              CLAIM_OPEN_HOUR, 0, 0, tzinfo=CN_TZ)
            wait = (target - now_cn).total_seconds()
            if wait > 0:
                # 分段睡到点（每次最多 1 小时），最后一跳落在 10:00:00 附近
                if wait > 3600:
                    _log(f"[benefit] 奶茶抢领等待 {wait:.0f}s 到 {CLAIM_OPEN_HOUR}:00:00", flush=True)
                time.sleep(min(wait, 3600))
                continue

            burst_dates.add(today)
            if started >= target:
                _log(f"[benefit] 奶茶抢领：启动时已过 {CLAIM_OPEN_HOUR}:00，今天不补抢，等明天那一轮", flush=True)
                continue

            _log(f"[benefit] 🧋 开始抢领兑换码活动 ({now_cn.strftime('%Y-%m-%d %H:%M:%S')} UTC+8)", flush=True)
            result = claim_coffee_card(is_cn=is_cn)
            status = result.get("status")
            if status in ("SKIPPED", "ALREADY_CLAIMED"):
                _log(f"[benefit] 奶茶本轮无需抢领: {result.get('reason') or result.get('campaignId')}", flush=True)
            elif status == "FAILED":
                _log(f"[benefit] 奶茶今日未抢到: {result.get('failureCode', result.get('error', '?'))}", flush=True)
            else:
                _log("[benefit] 🧋 奶茶免单卡已到手!", flush=True)
        except Exception as e:
            _log(f"[benefit] 奶茶抢领异常: {e}", flush=True)

        time.sleep(60)  # 每分钟检查一次是否到 10:00


def claim_coffee_now(is_cn: bool = True) -> dict:
    """立即抢领奶茶免单卡一次（手动测试用）"""
    return claim_coffee_card(is_cn=is_cn)
