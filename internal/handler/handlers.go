// Package handler 的协议路由，对应 Python 版 routes/{chat,completions,responses,
// anthropic}.py + server.py 的引擎调度段（_chat_direct_lines / _full_chat_direct /
// _openai_usage / _retry_wait）。模型门禁在路由层先挡：流式一旦开始产出，HTTP
// 状态码就改不了了，只能塞一条 SSE error 事件——很多 SDK 会当成网络故障重试。
package handler

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"qoder2api/internal/adapters"
	"qoder2api/internal/qoder"
)

// ── /v1/models ─────────────────────────────────────────────────────────────

// models 限免模型列表。标准字段之外多给 price_factor / is_free：OpenAI 客户端
// 会忽略不认识的字段，不破坏兼容性；这些字段能回答「为什么列表里只有这几个」。
func (s *Server) models(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.methodNotAllowed(w, r)
		return
	}
	now := time.Now().Unix()
	data := make([]any, 0)
	for _, e := range s.Q.ListModelEntries() {
		item := map[string]any{
			"id": e.Name, "object": "model", "created": now, "owned_by": "qoder",
			"price_factor": e.PriceFactor, "is_free": e.IsFree,
			"supports_vision": e.SupportsVision, "is_reasoning": e.IsReasoning,
		}
		if e.OriginalPriceFactor != nil {
			item["original_price_factor"] = e.OriginalPriceFactor
		}
		if e.ContextWindow != 0 {
			item["context_window"] = e.ContextWindow
		}
		data = append(data, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": data})
}

// ── 引擎调度参数 ─────────────────────────────────────────────────────────────

type chatParams struct {
	messages              []any
	model                 string
	includeUsage          bool
	temperature, topP     any
	topK, contextLength   any
	maxTokens             any
	tools                 []any
	toolChoice            any
	parallelToolCalls     any
	reasoningEffort       string
	enableThinking        any
	preserveThinking      bool
	reasoningBudgetTokens any
}

// ensureModel 路由层门禁：归一化模型名，非限免 → 400 model_not_allowed。
// errBody 由调用方按协议形状包（OpenAI JSON / Anthropic error_body）。
func (s *Server) ensureModel(w http.ResponseWriter, modelReq string, anthropicShape bool) (string, bool) {
	model, err := s.Q.EnsureFreeModel(modelReq)
	if err != nil {
		msg := err.Error()
		var mn *qoder.ModelNotAllowedError
		if errors.As(err, &mn) {
			msg = mn.Message
		}
		if anthropicShape {
			writeJSON(w, http.StatusBadRequest, adapters.AnthropicErrorBody("invalid_request_error", msg))
		} else {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]any{
				"message": msg, "type": "invalid_request_error", "code": "model_not_allowed"}})
		}
		return "", false
	}
	return model, true
}

// ── 重试决策（对应 Python _rate_limit_wait / _connect_wait / _retry_wait） ────

const (
	// 排队重试：10605/RESOURCE_LIMIT 是模型级容量信号（不是封号），实测常需
	// 3~5 轮 × 30s 才排到。默认 5 轮、单次等待上限 180s、总预算 300s，
	// 都可用环境变量覆盖（对齐 qoder2api-hub 的 QD_QUEUE_* 语义）。
	defaultQueueMaxRounds = 5
	defaultQueueMaxWait   = 180
	defaultQueueBudget    = 300
	connectRetryWait      = 2.0 // 连接类错误短退避
)

var (
	rateLimitMaxRetries = envInt("QODER_QUEUE_MAX_ROUNDS", defaultQueueMaxRounds)
	rateLimitMaxWait    = envFloat("QODER_QUEUE_WAIT_MAX_SECS", defaultQueueMaxWait)
	queueWaitBudget     = envFloat("QODER_QUEUE_WAIT_BUDGET_SECS", defaultQueueBudget)
	// queueMode 排队策略（对齐 qoder2api-hub 的 QD_QUEUE_WAIT_MODE）：
	//   visible —— 流式先发头，排队期间发心跳/提示，客户端能看到进度（默认）
	//   fast    —— 不等，直接 503 + Retry-After，让客户端自己重试
	//   wait    —— 静默 sleep（旧行为，客户端零字节会"卡住"，仅兼容保留）
	queueMode = strings.ToLower(strings.TrimSpace(orDefault(os.Getenv("QODER_QUEUE_WAIT_MODE"), "visible")))
)

// queueFast 是否快速失败模式（非 visible/wait 的未知值按 visible 处理）。
func queueFast() bool { return queueMode == "fast" }

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func envInt(name string, def int) int {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

var waitTimeRe = regexp.MustCompile(`"(waitTime|retryAfterSeconds)"\s*:\s*(\d+(?:\.\d+)?)`)

// rateLimitWait 从错误里识别上游排队限流（code 10605）并取 waitTime 秒数；
// 非限流错误返回 0。错误形如 HTTP 403: …{"code":"10605",…,"waitTime":30…}
func rateLimitWait(e error) float64 {
	if e == nil || !strings.Contains(e.Error(), "10605") {
		return 0
	}
	wait := 30.0 // 上游缺省值
	if m := waitTimeRe.FindStringSubmatch(e.Error()); m != nil {
		if f, err := strconv.ParseFloat(m[2], 64); err == nil {
			wait = f
		}
	}
	if wait > 0 && wait <= rateLimitMaxWait {
		return wait
	}
	return 0
}

// 说明：总预算 queueWaitBudget 的扣减在调用方的重试循环里做（见 chatDirectLines
// 与 direct 系列的 budget 变量），这里只负责把单次等待时长解析出来。

// connectErrSigns 连接类错误特征（依赖引擎把两类都包成 "upstream request failed: …"）。
var connectErrSigns = []string{"Max retries", "SSLEOFError", "SSLError", "ConnectionError",
	"ConnectionReset", "Connection aborted", "Connection reset",
	"Read timed out", "timed out", "ProtocolError", "ChunkedEncoding"}

// connectWait 连接类错误返回短退避秒数，其他返回 0。仅对未产出字节的请求安全。
func connectWait(e error) float64 {
	if e == nil {
		return 0
	}
	text := e.Error()
	if strings.Contains(text, "upstream request failed") && containsAny(text, connectErrSigns) {
		return connectRetryWait
	}
	return 0
}

// connectRetryMaxElapsed 一次尝试已耗掉这么久还不产出，多半是上游卡死而非瞬时
// 抖动（读超时是 QODER_TIMEOUT 秒）。用这个预算把慢失败限成只重试一次。
var connectRetryMaxElapsed = envFloat("QODER_CONNECT_RETRY_MAX_ELAPSED", 150)

// retryWait 统一重试决策：限流按 waitTime 睡等，连接错误短退避，其他不重试。
// elapsed 是本次请求已花掉的秒数，给「慢失败」限次。
func retryWait(e error, elapsed float64) float64 {
	if w := rateLimitWait(e); w > 0 {
		return w
	}
	w := connectWait(e)
	if w > 0 && elapsed > connectRetryMaxElapsed {
		return 0
	}
	return w
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func envFloat(name string, def float64) float64 {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

// ── usage 映射 ───────────────────────────────────────────────────────────────

// openaiUsage Qoder usage → OpenAI usage。上游按模型给不给计数：实测
// DeepSeek-Flash **压根不发 usage 事件**。调用方对拿不到的统一兜底 0——不能给
// null：很多 SDK 拿这个字段直接做算术（累计成本、算 TPS），null 会直接 TypeError。
func openaiUsage(u map[string]any) map[string]any {
	out := map[string]any{
		"prompt_tokens":     intOr(u["prompt_tokens"]),
		"completion_tokens": intOr(u["completion_tokens"]),
		"total_tokens":      intOr(u["total_tokens"]),
	}
	if cd, ok := u["completion_tokens_details"].(map[string]any); ok {
		out["completion_tokens_details"] = map[string]any{"reasoning_tokens": intOr(cd["reasoning_tokens"])}
	}
	if pd, ok := u["prompt_tokens_details"].(map[string]any); ok {
		out["prompt_tokens_details"] = map[string]any{"cached_tokens": intOr(pd["cached_tokens"])}
	}
	return out
}

func intOr(v any) int {
	if f, ok := v.(float64); ok {
		return int(f)
	}
	return 0
}

func zeroUsage() map[string]any {
	return map[string]any{"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
}

// ── 流式引擎接线（对应 Python _chat_direct_lines） ────────────────────────────

// chatDirectLines 产出 Chat SSE 原始行（带 data: 前缀，含 [DONE] 收尾帧）。
// chat 与 responses/anthropic 路由共用：后两者用 adapters 把这行流再包成各自方言。
// 限流（10605）按 waitTime 睡等、连接类错误短退避；均仅在尚未给客户端产出任何
// 字节时重试，否则透传错误。睡等期间发 ": keep-alive" 注释行心跳，防止 30s 等待
// 被 ai-sdk 之类的客户端掐断。
func (s *Server) chatDirectLines(ctx context.Context, p chatParams, cid string, now int64, rid string, t0 time.Time) iter.Seq[string] {
	return func(yield func(string) bool) {
		finishReason := ""
		roleSent := false
		var usage map[string]any

		chunk := func(delta map[string]any, fr any) string {
			return "data: " + string(marshalCompact(map[string]any{
				"id": cid, "object": "chat.completion.chunk", "created": now, "model": p.model,
				"choices": []any{map[string]any{"index": 0, "delta": delta, "finish_reason": fr}},
			})) + "\n\n"
		}

		produced := false // 已给客户端产出过真帧（心跳注释行不算）——出错后还能不能安全重试就看它
		frame := func(line string) bool {
			produced = true
			return yield(line)
		}

		var salvager *qoder.InvokeSalvage
		if len(p.tools) > 0 {
			salvager = &qoder.InvokeSalvage{}
		}
		tcIndex := 0
		salvagedAny := false

		attempts := 0
		errored := false
		for {
			var upErr error
			for ev := range s.Q.RunQoderCosy(qoder.RunParams{
				Messages: p.messages, Model: p.model, MaxTokens: p.maxTokens,
				ReasoningEffort: p.reasoningEffort, Temperature: p.temperature,
				TopP: p.topP, TopK: p.topK, ContextLength: p.contextLength,
				EnableThinking: p.enableThinking, PreserveThinking: p.preserveThinking,
				ReasoningBudgetTokens: p.reasoningBudgetTokens,
				Tools:                 p.tools, ToolChoice: p.toolChoice, ParallelToolCalls: p.parallelToolCalls,
			}) {
				if ev.Type == "error" {
					upErr = ev.Err
					break
				}
				if ctx.Err() != nil {
					return
				}
				switch ev.Type {
				case "finish":
					finishReason = ev.Reason
					continue
				case "usage":
					usage = openaiUsage(ev.Usage)
					continue
				case "content":
					if salvager != nil {
						// 正文回收：模型把工具调用写成 antml 文本（<invoke>…</invoke>）时
						// 拆回结构化 tool_calls；其余文本实时放行（有界前瞻 ≤14 字符）
						for _, se := range salvager.Feed(ev.Text) {
							if se.Kind == "text" && se.Text == "" {
								continue
							}
							delta := map[string]any{}
							if !roleSent {
								delta["role"] = "assistant"
								roleSent = true
							}
							if se.Kind == "text" {
								delta["content"] = se.Text
							} else {
								delta["tool_calls"] = []any{map[string]any{
									"index": tcIndex,
									"id":    "call_" + qoder.NewUUIDHex()[:24],
									"type":  "function",
									"function": map[string]any{
										"name":      se.Name,
										"arguments": string(marshalCompact(se.Params)),
									},
								}}
								tcIndex++
								salvagedAny = true
								s.Log.Info(rid + " antml回收 -> tool_call " + se.Name)
							}
							if !frame(chunk(delta, nil)) {
								return
							}
						}
						continue
					}
				}
				delta := map[string]any{}
				if !roleSent {
					delta["role"] = "assistant"
					roleSent = true
				}
				switch ev.Type {
				case "reasoning":
					delta["reasoning_content"] = ev.Text
				case "content":
					delta["content"] = ev.Text
				case "tool_calls":
					delta["tool_calls"] = ev.Delta
				}
				if !frame(chunk(delta, nil)) {
					return
				}
			}
			if upErr == nil {
				break
			}
			wait := retryWait(upErr, time.Since(t0).Seconds())
			// fast 模式：不等队列，直接告诉客户端多久后来（避免同步 HTTP 长时间挂住）
			if wait > 0 && queueFast() && !produced {
				errored = true
				s.Log.Warn(fmt.Sprintf("%s 排队(fast) %ds 后客户端可重试", rid, int(wait)))
				yield("data: " + string(marshalCompact(map[string]any{"error": map[string]any{
					"message": fmt.Sprintf("上游模型排队中，请 %d 秒后重试（模型级容量限制，与账号无关）", int(wait)),
					"type":    "rate_limit_error", "code": 503}})) + "\n\n")
				break
			}
			if produced || attempts >= rateLimitMaxRetries || wait <= 0 {
				errored = true
				s.Log.Warn(rid + " direct stream upstream error: " + upErr.Error())
				yield("data: " + string(marshalCompact(map[string]any{"error": map[string]any{
					"message": upErr.Error(), "type": "upstream_error", "code": errStatus(upErr)}})) + "\n\n")
				break
			}
			attempts++
			s.Log.Warn(fmt.Sprintf("%s 上游错误重试(%d)，%.0fs 后第 %d/%d 次",
				rid, errStatus(upErr), wait, attempts, rateLimitMaxRetries))
			deadline := time.Now().Add(time.Duration(wait * float64(time.Second)))
			for time.Now().Before(deadline) {
				d := time.Until(deadline)
				if d > 5*time.Second {
					d = 5 * time.Second
				}
				if d < 100*time.Millisecond {
					d = 100 * time.Millisecond
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(d):
				}
				if time.Now().Before(deadline) {
					if !yield(": keep-alive\n\n") {
						return
					}
				}
			}
			if !yield(": retrying\n\n") {
				return
			}
		}

		if !errored {
			// 回收器残留缓冲（未闭合块退回纯文本）；本回合回收过工具调用则收尾
			// 理由必须是 tool_calls，否则客户端会当成模型已说完
			if salvager != nil {
				for _, se := range salvager.Flush() {
					if se.Kind == "text" && se.Text != "" {
						if qoder.ContainsInvokeStart(se.Text) {
							s.Log.Warn(fmt.Sprintf("%s 未闭合 invoke 块降级纯文本（%d 字符）", rid, len(se.Text)))
						}
						frame(chunk(map[string]any{"content": se.Text}, nil))
					}
				}
				if salvagedAny && (finishReason == "" || finishReason == "stop") {
					finishReason = "tool_calls"
				}
			}
			fr := any(finishReason)
			if fr == "" {
				fr = "stop"
			}
			frame(chunk(map[string]any{}, fr))
			if p.includeUsage {
				u := usage
				if u == nil {
					u = zeroUsage() // DeepSeek-Flash 这类模型上游压根不发 usage
				}
				frame("data: " + string(marshalCompact(map[string]any{
					"id": cid, "object": "chat.completion.chunk", "created": now, "model": p.model,
					"choices": []any{}, "usage": u,
				})) + "\n\n")
			}
		}
		yield("data: [DONE]\n\n")
	}
}

// errStatus UpstreamError 的状态码（其他错误 502）。
func errStatus(e error) int {
	var ue *qoder.UpstreamError
	if errors.As(e, &ue) {
		return ue.Status
	}
	return 502
}

// ── 非流式引擎接线（对应 Python _full_chat_direct） ──────────────────────────

// fullChatDirect 聚合完整响应。非流式在聚合开始前整体重试是安全的（无半截内容）；
// 限流按 waitTime、连接错误短退避，持续失败则透传错误 JSON（ok=false）。
func (s *Server) fullChatDirect(ctx context.Context, p chatParams, cid string, now int64, rid string, t0 time.Time) (map[string]any, bool) {
	var contentParts, thinkingParts []string
	toolCalls := map[int]map[string]any{}
	finishReason := ""
	var usage map[string]any
	attempts := 0
	for {
		var upErr error
		for ev := range s.Q.RunQoderCosy(qoder.RunParams{
			Messages: p.messages, Model: p.model, MaxTokens: p.maxTokens,
			ReasoningEffort: p.reasoningEffort, Temperature: p.temperature,
			TopP: p.topP, TopK: p.topK, ContextLength: p.contextLength,
			EnableThinking: p.enableThinking, PreserveThinking: p.preserveThinking,
			ReasoningBudgetTokens: p.reasoningBudgetTokens,
			Tools:                 p.tools, ToolChoice: p.toolChoice, ParallelToolCalls: p.parallelToolCalls,
		}) {
			if ev.Type == "error" {
				upErr = ev.Err
				break
			}
			if ctx.Err() != nil {
				return nil, false
			}
			switch ev.Type {
			case "reasoning":
				thinkingParts = append(thinkingParts, ev.Text)
			case "content":
				contentParts = append(contentParts, ev.Text)
			case "usage":
				usage = openaiUsage(ev.Usage)
			case "finish":
				finishReason = ev.Reason
			case "tool_calls":
				mergeToolCall(toolCalls, ev.Delta)
			}
		}
		if upErr == nil {
			break
		}
		wait := retryWait(upErr, time.Since(t0).Seconds())
		// fast 模式：不睡队列，直接回 503 + Retry-After 让客户端自己重试
		if wait > 0 && queueFast() {
			s.Log.Warn(fmt.Sprintf("%s 排队(fast) %ds 后客户端可重试", rid, int(wait)))
			return map[string]any{"error": map[string]any{
				"message":     fmt.Sprintf("上游模型排队中，请 %d 秒后重试（模型级容量限制，与账号无关）", int(wait)),
				"type":        "rate_limit_error",
				"code":        503,
				"retry_after": int(wait),
			}}, false
		}
		if attempts >= rateLimitMaxRetries || wait <= 0 {
			s.Log.Warn(rid + " direct upstream error: " + upErr.Error())
			return map[string]any{"error": map[string]any{
				"message": upErr.Error(), "type": "upstream_error", "code": errStatus(upErr)}}, false
		}
		attempts++
		s.Log.Warn(fmt.Sprintf("%s 上游错误重试(%d)，%.0fs 后第 %d/%d 次",
			rid, errStatus(upErr), wait, attempts, rateLimitMaxRetries))
		time.Sleep(time.Duration(wait * float64(time.Second)))
	}

	content := cat(contentParts)
	// 非流式回收：模型把工具调用写成 antml 文本时拆回结构化 tool_calls
	//（解析失败降级纯文本；回收的调用排在原有 tool_calls 之后）
	if len(p.tools) > 0 && content != "" {
		var salv qoder.InvokeSalvage
		events := append(salv.Feed(content), salv.Flush()...)
		texts := []string{}
		var calls []map[string]any
		for _, se := range events {
			if se.Kind == "text" {
				texts = append(texts, se.Text)
			} else {
				calls = append(calls, map[string]any{
					"id": "call_" + qoder.NewUUIDHex()[:24], "type": "function",
					"function": map[string]any{"name": se.Name, "arguments": string(marshalCompact(se.Params))},
				})
			}
		}
		content = cat(texts)
		if len(calls) > 0 {
			names := make([]string, 0, len(calls))
			for _, c := range calls {
				names = append(names, c["function"].(map[string]any)["name"].(string))
			}
			s.Log.Info(rid + " antml回收 -> tool_call " + fmt.Sprint(names))
			base := 0
			for k := range toolCalls {
				if k >= base {
					base = k + 1
				}
			}
			for i, c := range calls {
				toolCalls[base+i] = c
			}
		}
	}

	message := map[string]any{"role": "assistant", "content": content}
	if len(thinkingParts) > 0 {
		message["reasoning_content"] = cat(thinkingParts)
	}
	u := usage
	if u == nil {
		u = zeroUsage()
	}
	result := map[string]any{
		"id": cid, "object": "chat.completion", "created": now, "model": p.model,
		"choices": []any{map[string]any{"index": 0, "message": message, "finish_reason": finishReason}},
		"usage":   u,
	}
	if len(toolCalls) > 0 {
		keys := make([]int, 0, len(toolCalls))
		for k := range toolCalls {
			keys = append(keys, k)
		}
		sort.Ints(keys)
		arr := make([]any, 0, len(keys))
		for _, k := range keys {
			arr = append(arr, toolCalls[k])
		}
		message["tool_calls"] = arr
		result["choices"].([]any)[0].(map[string]any)["finish_reason"] = "tool_calls"
	} else if content == "" {
		message["content"] = nil // 空 content 统一 null（OpenAI 语义）
	}
	return result, true
}

func cat(parts []string) string {
	return strings.Join(parts, "")
}

// mergeToolCall 增量 tool_calls 按 index 拼接。
func mergeToolCall(toolCalls map[int]map[string]any, delta []any) {
	for _, tci := range delta {
		tc, _ := tci.(map[string]any)
		if tc == nil {
			continue
		}
		idx := intOr(tc["index"])
		if _, ok := tc["index"]; !ok {
			idx = len(toolCalls)
		}
		slot, ok := toolCalls[idx]
		if !ok {
			slot = map[string]any{
				"id": "", "type": "function",
				"function": map[string]any{"name": "", "arguments": ""},
			}
			toolCalls[idx] = slot
		}
		if id, _ := tc["id"].(string); id != "" {
			slot["id"] = id
		}
		if fn, _ := tc["function"].(map[string]any); fn != nil {
			fslot := slot["function"].(map[string]any)
			if n, _ := fn["name"].(string); n != "" {
				fslot["name"] = fslot["name"].(string) + n
			}
			if a, _ := fn["arguments"].(string); a != "" {
				fslot["arguments"] = fslot["arguments"].(string) + a
			}
		}
	}
}

// ── /v1/chat/completions ────────────────────────────────────────────────────

func (s *Server) chat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.methodNotAllowed(w, r)
		return
	}
	info := reqInfoFrom(r)
	body := info.payload
	messages, _ := body["messages"].([]any)
	modelReq := str(body["model"])
	stream, _ := body["stream"].(bool)

	if len(messages) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]any{
			"message": "messages is required", "type": "invalid_request_error"}})
		return
	}
	model, ok := s.ensureModel(w, modelReq, false)
	if !ok {
		return
	}
	if tc, ok := body["tool_choice"].(string); ok && tc != "auto" && tc != "none" && tc != "required" {
		s.Log.Warn(fmt.Sprintf("%s tool_choice=%q 非 OpenAI 取值，不送上游", info.rid, tc))
	}

	p := chatParams{
		messages: messages, model: model,
		maxTokens:   firstOf(body["max_completion_tokens"], body["max_tokens"]),
		temperature: body["temperature"], topP: body["top_p"], topK: body["top_k"],
		contextLength: body["context_length"],
		tools:         toSlice(body["tools"]), toolChoice: body["tool_choice"],
		parallelToolCalls:     body["parallel_tool_calls"],
		reasoningEffort:       str(body["reasoning_effort"]),
		enableThinking:        body["enable_thinking"],
		preserveThinking:      boolOr(body["preserve_thinking"]),
		reasoningBudgetTokens: body["reasoning_budget_tokens"],
	}
	if so, ok := body["stream_options"].(map[string]any); ok {
		p.includeUsage, _ = so["include_usage"].(bool)
	}
	cid := "chatcmpl-" + qoder.NewUUIDHex()
	now := time.Now().Unix()

	if stream {
		s.writeSSE(w, r, s.chatDirectLines(r.Context(), p, cid, now, info.rid, info.t0))
		return
	}
	result, ok2 := s.fullChatDirect(r.Context(), p, cid, now, info.rid, info.t0)
	if !ok2 {
		writeJSON(w, respErrStatus(result), result)
		return
	}
	out := marshalCompact(result)
	s.doneLog(info.rid, "status=200", len(out), info.t0)
	s.Dump.Save(info.rid, "resp", string(out))
	writeJSON(w, http.StatusOK, result)
}

// respErrStatus 错误结果 map 里记的状态码（fullChatDirect 失败路径）。
func respErrStatus(result map[string]any) int {
	if e, ok := result["error"].(map[string]any); ok {
		switch c := e["code"].(type) {
		case int:
			return c
		case float64:
			return int(c)
		}
	}
	return 502
}

func firstOf(vals ...any) any {
	for _, v := range vals {
		if f, ok := v.(float64); ok && f > 0 {
			return v
		}
	}
	return nil
}

func toSlice(v any) []any {
	l, _ := v.([]any)
	return l
}

func boolOr(v any) bool {
	b, _ := v.(bool)
	return b
}

// ── /v1/completions（legacy 文本补全） ───────────────────────────────────────

// promptToText OpenAI prompt 参数：str 或 str 数组 → 纯文本；token 数组不支持
// （本地没有 tokenizer，硬编会静默给错答案）。
func promptToText(prompt any) (string, bool) {
	switch p := prompt.(type) {
	case string:
		return p, true
	case []any:
		if len(p) == 0 {
			return "", true
		}
		allStr, allInt := true, true
		for _, x := range p {
			switch x.(type) {
			case string:
				allInt = false
			case float64:
				allStr = false
			default:
				allStr, allInt = false, false
			}
		}
		if allStr {
			parts := make([]string, 0, len(p))
			for _, x := range p {
				parts = append(parts, x.(string))
			}
			return strings.Join(parts, "\n"), true
		}
		if allInt {
			return "", false
		}
	}
	return "", false
}

func (s *Server) completions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.methodNotAllowed(w, r)
		return
	}
	info := reqInfoFrom(r)
	body := info.payload
	model, ok := s.ensureModel(w, str(body["model"]), false)
	if !ok {
		return
	}
	text, supported := promptToText(body["prompt"])
	if !supported {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]any{
			"message": "token-array prompt is not supported", "type": "invalid_request_error"}})
		return
	}
	if text == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]any{
			"message": "prompt is required", "type": "invalid_request_error"}})
		return
	}
	p := chatParams{
		messages:    []any{map[string]any{"role": "user", "content": text}},
		model:       model,
		maxTokens:   body["max_tokens"],
		temperature: body["temperature"],
	}
	cid := "cmpl-" + qoder.NewUUIDHex()
	now := time.Now().Unix()

	if boolOr(body["stream"]) {
		s.writeSSE(w, r, s.completionsLines(r.Context(), p, cid, now, info.rid))
		return
	}
	// 非流式文本补全：只输出正文，reasoning 不外泄
	var parts []string
	finishReason := ""
	var usage map[string]any
	for ev := range s.Q.RunQoderCosy(qoder.RunParams{
		Messages: p.messages, Model: p.model, MaxTokens: p.maxTokens, Temperature: p.temperature}) {
		if ev.Type == "error" {
			writeJSON(w, errStatus(ev.Err), map[string]any{"error": map[string]any{
				"message": ev.Err.Error(), "type": errTypeOf(ev.Err), "code": errStatus(ev.Err)}})
			return
		}
		switch ev.Type {
		case "content":
			parts = append(parts, ev.Text)
		case "usage":
			usage = openaiUsage(ev.Usage)
		case "finish":
			finishReason = ev.Reason
		}
	}
	if finishReason == "" {
		finishReason = "stop"
	}
	u := usage
	if u == nil {
		u = zeroUsage()
	}
	result := map[string]any{
		"id": cid, "object": "text_completion", "created": now, "model": model,
		"choices": []any{map[string]any{"index": 0, "text": cat(parts), "finish_reason": finishReason}},
		"usage":   u,
	}
	out := marshalCompact(result)
	s.doneLog(info.rid, "status=200", len(out), info.t0)
	s.Dump.Save(info.rid, "resp", string(out))
	writeJSON(w, http.StatusOK, result)
}

// completionsLines 流式文本补全：text_completion_chunk 帧，只输出正文。
func (s *Server) completionsLines(ctx context.Context, p chatParams, cid string, now int64, rid string) iter.Seq[string] {
	return func(yield func(string) bool) {
		finishReason := ""
		chunk := func(text string, fr any) string {
			return "data: " + string(marshalCompact(map[string]any{
				"id": cid, "object": "text_completion_chunk", "created": now, "model": p.model,
				"choices": []any{map[string]any{"index": 0, "text": text, "finish_reason": fr}},
			})) + "\n\n"
		}
		errored := false
		for ev := range s.Q.RunQoderCosy(qoder.RunParams{
			Messages: p.messages, Model: p.model, MaxTokens: p.maxTokens, Temperature: p.temperature}) {
			if ev.Type == "error" {
				errored = true
				s.Log.Warn(rid + " direct completions upstream error: " + ev.Err.Error())
				yield("data: " + string(marshalCompact(map[string]any{"error": map[string]any{
					"message": ev.Err.Error(), "type": errTypeOf(ev.Err), "code": errStatus(ev.Err)}})) + "\n\n")
				break
			}
			if ctx.Err() != nil {
				return
			}
			if ev.Type == "content" {
				if !yield(chunk(ev.Text, nil)) {
					return
				}
			} else if ev.Type == "finish" {
				finishReason = ev.Reason
			}
		}
		if !errored {
			fr := any(finishReason)
			if fr == "" {
				fr = "stop"
			}
			yield(chunk("", fr))
		}
		yield("data: [DONE]\n\n")
	}
}

func errTypeOf(e error) string {
	if errStatus(e) != 502 {
		return "upstream_error"
	}
	return "api_error"
}

// ── /v1/responses ───────────────────────────────────────────────────────────

func (s *Server) responses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.methodNotAllowed(w, r)
		return
	}
	info := reqInfoFrom(r)
	body := info.payload
	if len(body) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]any{
			"message": "invalid request: JSON object body required", "type": "invalid_request_error"}})
		return
	}
	chatBody := adapters.ResponsesToChat(body)
	messages, _ := chatBody["messages"].([]any)
	if len(messages) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]any{
			"message": "invalid request: 'input' is required", "type": "invalid_request_error"}})
		return
	}
	model, ok := s.ensureModel(w, str(chatBody["model"]), false)
	if !ok {
		return
	}
	p := s.paramsFromBody(chatBody, messages, model)
	cid := "resp-" + qoder.NewUUIDHex()
	now := time.Now().Unix()

	if boolOr(chatBody["stream"]) {
		lines := s.chatDirectLines(r.Context(), p, cid, now, info.rid, info.t0)
		s.writeSSE(w, r, strSeq(adapters.ChatSSEToResponses(adapters.SSELines{Seq: lines}, model)))
		return
	}
	result, ok2 := s.fullChatDirect(r.Context(), p, cid, now, info.rid, info.t0)
	if !ok2 {
		writeJSON(w, respErrStatus(result), result)
		return
	}
	out := marshalCompact(adapters.ChatJSONToResponses(result, model))
	s.doneLog(info.rid, "status=200", len(out), info.t0)
	s.Dump.Save(info.rid, "resp", string(out))
	writeRawJSON(w, http.StatusOK, out)
}

// ── /v1/messages（Anthropic） ────────────────────────────────────────────────

func (s *Server) anthropic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.methodNotAllowed(w, r)
		return
	}
	info := reqInfoFrom(r)
	body := info.payload
	if len(body) == 0 {
		writeJSON(w, http.StatusBadRequest, adapters.AnthropicErrorBody(
			"invalid_request_error", "invalid request: JSON object body required"))
		return
	}
	chatBody := adapters.AnthropicToChat(body)
	messages, _ := chatBody["messages"].([]any)
	if len(messages) == 0 {
		writeJSON(w, http.StatusBadRequest, adapters.AnthropicErrorBody(
			"invalid_request_error", "invalid request: 'messages' is required"))
		return
	}
	model, ok := s.ensureModel(w, str(chatBody["model"]), true)
	if !ok {
		return
	}
	p := s.paramsFromBody(chatBody, messages, model)
	cid := "msg_" + qoder.NewUUIDHex()
	now := time.Now().Unix()

	if boolOr(chatBody["stream"]) {
		lines := s.chatDirectLines(r.Context(), p, cid, now, info.rid, info.t0)
		s.writeSSE(w, r, strSeq(adapters.ChatSSEToAnthropic(lines, model)))
		return
	}
	result, ok2 := s.fullChatDirect(r.Context(), p, cid, now, info.rid, info.t0)
	if !ok2 {
		writeJSON(w, respErrStatus(result), adapters.AnthropicErrorBody(
			"api_error", errMsgOf(result)))
		return
	}
	out := marshalCompact(adapters.ChatJSONToAnthropic(result, model))
	s.doneLog(info.rid, "status=200", len(out), info.t0)
	s.Dump.Save(info.rid, "resp", string(out))
	writeRawJSON(w, http.StatusOK, out)
}

// errMsgOf 错误结果 map 里的 message（fullChatDirect 失败路径）。
func errMsgOf(result map[string]any) string {
	if e, ok := result["error"].(map[string]any); ok {
		return str(e["message"])
	}
	return "upstream error"
}

// paramsFromBody 从翻译后的 chat body 组装引擎参数（responses/anthropic 共用）。
func (s *Server) paramsFromBody(chatBody map[string]any, messages []any, model string) chatParams {
	p := chatParams{
		messages: messages, model: model,
		maxTokens:   firstOf(chatBody["max_completion_tokens"], chatBody["max_tokens"]),
		temperature: chatBody["temperature"], topP: chatBody["top_p"], topK: chatBody["top_k"],
		contextLength: chatBody["context_length"],
		tools:         toSlice(chatBody["tools"]), toolChoice: chatBody["tool_choice"],
		parallelToolCalls:     chatBody["parallel_tool_calls"],
		reasoningEffort:       str(chatBody["reasoning_effort"]),
		enableThinking:        chatBody["enable_thinking"],
		preserveThinking:      boolOr(chatBody["preserve_thinking"]),
		reasoningBudgetTokens: chatBody["reasoning_budget_tokens"],
	}
	if so, ok := chatBody["stream_options"].(map[string]any); ok {
		p.includeUsage, _ = so["include_usage"].(bool)
	}
	return p
}

// strSeq 字节行流 → 字符串行流（adapters 产出 []byte 帧，writeSSE 吃 string）。
func strSeq(seq iter.Seq[[]byte]) iter.Seq[string] {
	return func(yield func(string) bool) {
		for b := range seq {
			if !yield(string(b)) {
				return
			}
		}
	}
}

// writeRawJSON 写出已序列化的 JSON（writeJSON 会对 []byte 再包一层引号）。
func writeRawJSON(w http.ResponseWriter, status int, data []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

// methodNotAllowed 方法不对（Python errorhandler 405）。
func (s *Server) methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": map[string]any{
		"message": "Not Found: " + r.URL.Path, "type": "invalid_request_error"}})
}

// ── /login、/login/status（非阻塞 device flow） ──────────────────────────────

var loginState = struct {
	mu    sync.Mutex
	st    string // idle | pending | ok | failed
	email string
	err   string
}{st: "idle"}

// login 后台启动 device flow：立即回 pending，浏览器授权完成后 /login/status 变 ok。
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	loginState.mu.Lock()
	if loginState.st == "pending" {
		st := loginState.st
		loginState.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"status": st})
		return
	}
	loginState.st = "pending"
	loginState.err, loginState.email = "", ""
	loginState.mu.Unlock()

	go func() {
		cred, err := s.Q.DeviceFlowSignIn()
		loginState.mu.Lock()
		defer loginState.mu.Unlock()
		if err != nil || cred == nil {
			loginState.st = "failed"
			loginState.err = "授权超时或被拒绝"
			if err != nil {
				loginState.err = err.Error()
			}
			return
		}
		s.Q.SaveCred(cred)
		loginState.st = "ok"
		loginState.email = cred.Email
	}()
	writeJSON(w, http.StatusOK, map[string]any{"status": "pending"})
}

func (s *Server) loginStatus(w http.ResponseWriter, r *http.Request) {
	loginState.mu.Lock()
	defer loginState.mu.Unlock()
	body := map[string]any{"status": loginState.st}
	if loginState.email != "" {
		body["email"] = loginState.email
	}
	if loginState.err != "" {
		body["error"] = loginState.err
	}
	writeJSON(w, http.StatusOK, body)
}
