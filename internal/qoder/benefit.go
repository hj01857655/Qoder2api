// Package qoder 的每日额度签到（对应 Python lanes/benefit.py）：
// 查活动列表 → 领所有 CLAIMABLE 活动 → 按服务端轮次窗口排期的后台循环。
//
// 结论码与重试纪律：只有拿到确定性结论（CLAIMED / ALREADY_CLAIMED_TODAY）才把
// 本轮推迟到 endAt 之后；查询失败、领取失败、活动未投放都按 CHECK_INTERVAL 重试
// ——把这三类也当「已签」会造成「积分长期不涨还没人报错」。
package qoder

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	checkInterval      = time.Hour
	campaignsPath      = "/sash/api/v1/me/campaigns"
	usagePath          = "/sash/api/v2/me/usage"
	reasonClaimed      = "CLAIMED"               // 本轮领到了
	reasonAlready      = "ALREADY_CLAIMED_TODAY" // 服务端回显：这一轮已领过
	reasonNotDelivered = "NOT_DELIVERED"         // 列表里没有 CREDITS 活动（账号不匹配或被风控隐藏）
	reasonQueryFailed  = "QUERY_FAILED"          // 活动列表没查到（HTTP 非 200 / 重试耗尽）
	reasonClaimFailed  = "CLAIM_FAILED"          // 查到可领但领取失败
)

// Benefit 签到器：复用引擎的身份与 openapi 通道。
type Benefit struct {
	C        *Client
	MarkPath string // REDEMPTION_CODE 兑换码的本地已领标记（每人限领一次）
	Log      func(msg string)
}

func (b *Benefit) logf(format string, a ...any) {
	if b.Log != nil {
		b.Log("[benefit] " + fmt.Sprintf(format, a...))
	}
}

// benefitHeaders campaigns 投放按头组合路由，两条实测约束（2026-10-12）：
//  1. `Cosy-ClientType: 10` 必带，缺了服务端 showCampaign=false 且活动列表为空。
//  2. **不能带 `Cosy-MachineToken`**：该头被当成风控指纹，值非真机时每日 CREDITS
//     活动直接从 campaigns 响应里消失（claimable=false）。只带 MachineId 或只带
//     MachineType 均不影响投放，故保留二者、丢弃 Token。
func (b *Benefit) headers(token string) map[string]string {
	mid := ""
	if cred, err := b.C.LoadIdentity(false); err == nil {
		mid = b.C.MachineID(cred)
	}
	hostname, _ := os.Hostname()
	return map[string]string{
		"Authorization":        "Bearer " + token,
		"Accept":               "application/json",
		"Content-Type":         "application/json",
		"User-Agent":           "Qoder",
		"Cosy-ClientType":      "10",
		"Cosy-Version":         "0.4.3",
		"Cosy-MachineOS":       "win32",
		"Cosy-MachineId":       mid,
		"Cosy-MachineType":     "5",
		"Cosy-MachineHostname": hostname,
	}
}

// benefitRequest 带退避重试的请求；openapi 偶发 TLS 握手中断（约 7 次里 2 次
// SSLEOFError），一次失败不代表业务结果，必须退避重试后再下结论。
func (b *Benefit) benefitRequest(method, url string, headers map[string]string) (int, []byte, error) {
	var lastErr error
	for i := 0; i < 4; i++ {
		ctx, cancel := contextWithTimeout(openapiTimeoutS * time.Second)
		req, err := http.NewRequestWithContext(ctx, method, url, nil)
		if err == nil {
			for k, v := range headers {
				req.Header.Set(k, v)
			}
			resp, err := b.C.httpc().Do(req)
			if err == nil {
				defer resp.Body.Close()
				body, _ := ioReadAll(ioLimit(resp.Body, 8<<20))
				cancel()
				return resp.StatusCode, body, nil
			}
			lastErr = err
		} else {
			lastErr = err
		}
		cancel()
		if i < 3 {
			time.Sleep(time.Duration(1500*(i+1)) * time.Millisecond)
		}
	}
	return 0, nil, lastErr
}

func benefitKind(c map[string]any) string {
	b, _ := c["benefit"].(map[string]any)
	if b == nil {
		return ""
	}
	s, _ := b["kind"].(string)
	return s
}

func brief(c map[string]any) string {
	b, _ := c["benefit"].(map[string]any)
	kind, amount, status := "", "", ""
	if b != nil {
		kind, _ = b["kind"].(string)
		amount = fmt.Sprint(b["amount"])
	}
	status = fmt.Sprint(c["claimStatus"])
	return fmt.Sprintf("%s kind=%s amount=%s status=%s", c["campaignKey"], kind, amount, status)
}

// CheckCampaigns 查活动状态。带 error 表示「没拿到可信结果」——和「确实没有可领
// 活动」是两回事，调用方必须区分，否则一次抖动就会被当成今日已签到。
func (b *Benefit) CheckCampaigns() (map[string]any, error) {
	cred, err := b.C.LoadIdentity(false)
	if err != nil {
		return nil, fmt.Errorf("no credential (run: qoder2api login)")
	}
	token := cred.AccessToken
	status, body, err := b.benefitRequest(http.MethodGet,
		b.C.OpenAPIHost+campaignsPath, b.headers(token))
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("HTTP %d: %s", status, truncStr(string(body), 200))
	}
	var data map[string]any
	if jsonUnmarshal(body, &data) != nil || data == nil {
		data = map[string]any{}
	}
	campaigns, _ := data["campaigns"].([]any)
	claimable := []any{}
	for _, ci := range campaigns {
		c, ok := ci.(map[string]any)
		if !ok {
			continue
		}
		if s, _ := c["claimStatus"].(string); s == "CLAIMABLE" {
			claimable = append(claimable, c)
		}
	}
	return map[string]any{
		"showCampaign":        data["showCampaign"],
		"claimable":           len(claimable) > 0,
		"campaigns":           campaigns,
		"claimable_campaigns": claimable,
	}, nil
}

// ClaimCampaign 领取活动奖励。成功判定只看 status == "CLAIMED"；replayed 是
// 服务端幂等回显（此前已领），不算新发放。
func (b *Benefit) ClaimCampaign(campaignID string) map[string]any {
	cred, err := b.C.LoadIdentity(false)
	if err != nil {
		return map[string]any{"error": "no credential (run: qoder2api login)", "status": "FAILED"}
	}
	status, body, err := b.benefitRequest(http.MethodPost,
		b.C.OpenAPIHost+campaignsPath+"/"+campaignID+"/claim", b.headers(cred.AccessToken))
	if err != nil {
		b.logf("❌ 领取异常: %v", err)
		return map[string]any{"error": err.Error(), "status": "FAILED"}
	}
	if status != 200 {
		b.logf("❌ 领取失败: HTTP %d %s", status, truncStr(string(body), 200))
		return map[string]any{"error": fmt.Sprintf("HTTP %d", status), "body": truncStr(string(body), 500), "status": "FAILED"}
	}
	var data map[string]any
	if jsonUnmarshal(body, &data) != nil || data == nil {
		data = map[string]any{}
	}
	bb, _ := data["benefit"].(map[string]any)
	tag := "新发放"
	if boolOr(data["replayed"]) {
		tag = "幂等回显（此前已领）"
	}
	if s, _ := data["status"].(string); s == "CLAIMED" {
		key := campaignID
		if k, _ := data["campaignKey"].(string); k != "" {
			key = k
		}
		b.logf("✅ 领取成功 %s x%s（%s） campaign=%s", bb["kind"], fmt.Sprint(bb["amount"]), tag, key)
	} else {
		failure := fmt.Sprint(data["status"])
		if fc, _ := data["failureCode"].(string); fc != "" {
			failure = fc
		}
		b.logf("❌ 领取未成功: %s（%s）", failure, tag)
	}
	return data
}

// readCoffeeMarks / markCoffeeClaimed 兑换码每人限领一次，按 campaignId 落标，
// 重启后不重复扰服务端。
func (b *Benefit) readCoffeeMarks() map[string]bool {
	marks := map[string]bool{}
	data, err := os.ReadFile(b.MarkPath)
	if err != nil {
		return marks
	}
	var m map[string]any
	if jsonUnmarshal(data, &m) == nil && m != nil {
		for k, v := range m {
			if boolOr(v) {
				marks[k] = true
			}
		}
	}
	return marks
}

func (b *Benefit) markCoffeeClaimed(campaignID string) {
	if b.MarkPath == "" {
		return
	}
	marks := b.readCoffeeMarks()
	marks[campaignID] = true
	data, err := marshalCompact(marks)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(b.MarkPath), 0o700); err != nil {
		return
	}
	_ = os.WriteFile(b.MarkPath, data, 0o600)
}

// CheckAndClaim 检查并自动签到（全自动）。返回带 reason 的结论，供线程决定是否
// 把今天记账。不按本地钟点拦截：服务端已经按轮次发了 startAt/endAt，
// 00:00-09:59 依旧可能有一个未领的上一轮（官方规则：错过不补领、不累计）。
func (b *Benefit) CheckAndClaim() map[string]any {
	result := map[string]any{
		"time":          time.Now().Format(time.RFC3339),
		"claimable":     false,
		"claimed":       false,
		"campaigns":     []any{},
		"claim_results": []any{},
		"reason":        nil,
	}
	status, err := b.CheckCampaigns()
	if err != nil {
		result["error"] = err.Error()
		result["reason"] = reasonQueryFailed
		b.logf("活动列表查询失败（%v），本轮不记账，下一轮重试", err)
		return result
	}

	result["claimable"] = status["claimable"]
	campaigns, _ := status["campaigns"].([]any)
	result["campaigns"] = campaigns

	if claimable, _ := status["claimable"].(bool); !claimable {
		// 按 benefit.kind 到底有没有投放来区分成因
		delivered := false
		for _, ci := range campaigns {
			if c, ok := ci.(map[string]any); ok && benefitKind(c) == "CREDITS" {
				delivered = true
				break
			}
		}
		reason := reasonNotDelivered
		if delivered {
			reason = reasonAlready
		}
		result["reason"] = reason
		briefs := []string{}
		for _, ci := range campaigns {
			if c, ok := ci.(map[string]any); ok {
				briefs = append(briefs, brief(c))
			}
		}
		b.logf("无可领活动（%s），服务端投放: %v", reason, briefs)
		return result
	}

	skipped, failed := 0, 0
	claimable, _ := status["claimable_campaigns"].([]any)
	claimResults, _ := result["claim_results"].([]any)
	for _, ci := range claimable {
		c, ok := ci.(map[string]any)
		if !ok {
			continue
		}
		cid, _ := c["campaignId"].(string)
		if benefitKind(c) == "REDEMPTION_CODE" && b.readCoffeeMarks()[cid] {
			b.logf("%s 本地标记已领过，跳过 claim", c["campaignKey"])
			skipped++
			continue
		}
		claimResult := b.ClaimCampaign(cid)
		claimResults = append(claimResults, claimResult)
		result["claim_results"] = claimResults
		if s, _ := claimResult["status"].(string); s == "CLAIMED" {
			result["claimed"] = true
			if benefitKind(c) == "REDEMPTION_CODE" {
				b.markCoffeeClaimed(cid)
			}
		} else {
			failed++
		}
	}

	switch {
	case boolOr(result["claimed"]):
		result["reason"] = reasonClaimed
	case skipped > 0 && failed == 0:
		result["reason"] = reasonAlready
	default:
		result["reason"] = reasonClaimFailed
	}
	return result
}

// roundEnd 本轮（CREDITS 活动）的截止时刻 + 1 分钟，即下一轮开放瞬间。
// 服务端给的是 UTC 秒（实测 endAt 落在 09:59，+1min 正好 10:00:00）。
func (b *Benefit) roundEnd(result map[string]any) time.Time {
	campaigns, _ := result["campaigns"].([]any)
	for _, ci := range campaigns {
		c, ok := ci.(map[string]any)
		if !ok || benefitKind(c) != "CREDITS" {
			continue
		}
		if endAt := numOrZero(c["endAt"]); endAt > 0 {
			return time.Unix(int64(endAt), 0).In(cnTZ).Add(time.Minute)
		}
	}
	return time.Time{}
}

// StartDailyLoop 签到线程主循环：按服务端的轮次窗口排期，不按自然日、也不卡
// 10:00 钟点。启动即查一次；此后确定性结论推到本轮 endAt 之后，其余每小时重试。
// 该函数阻塞，调用方放 goroutine。
func (b *Benefit) StartDailyLoop() {
	nextCheck := time.Now().In(cnTZ) // 初值 = 启动就查一次
	for {
		nowCN := time.Now().In(cnTZ)
		if !nextCheck.After(nowCN) {
			b.logf("签到检查 (%s)", nowCN.Format("2006-01-02 15:04"))
			result := b.CheckAndClaim()
			reason, _ := result["reason"].(string)
			if reason == reasonClaimed || reason == reasonAlready {
				if end := b.roundEnd(result); !end.IsZero() {
					nextCheck = end
				} else {
					nextCheck = nowCN.Add(checkInterval)
				}
				b.logf("本轮已了结（%s），下一轮 %s 再查", reason, nextCheck.Format("01-02 15:04:05"))
			} else {
				// NOT_DELIVERED / 查询或领取失败：活动可能晚点才投放，每小时重试
				nextCheck = nowCN.Add(checkInterval)
				b.logf("本轮不记账（%s），稍后重试", reason)
			}
		}
		// 距下次检查不足一小时时精确落到点，更远时每小时醒一次
		delay := nextCheck.Sub(time.Now())
		if delay > checkInterval {
			delay = checkInterval
		}
		if delay < time.Second {
			delay = time.Second
		}
		time.Sleep(delay)
	}
}

// cnTZ UTC+8（Python CN_TZ）。签到日志与轮次窗口都按东八区。
var cnTZ = time.FixedZone("UTC+8", 8*3600)
