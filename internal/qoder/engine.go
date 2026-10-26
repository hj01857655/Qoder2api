// Package qoder 的推理引擎，对应 Python lanes/qoder_cosy.py 的请求体构建段与
// run_qoder_cosy：build_request_body（参数映射 + system 注入 + 编码）、
// _ThinkSplitter（跨 chunk 的 <think> 内联标签分流）、run_qoder_cosy
// （COSY SSE 信封解析 → 事件流）。
package qoder

import (
	"bufio"
	"fmt"
	"io"
	"iter"
	"net/http"
	"regexp"
	"strings"
	"time"

	"qoder2api/internal/proto"
)

// RunParams 一次推理调用的参数（对应 run_qoder_cosy 的关键字参数）。
type RunParams struct {
	Messages              []any // OpenAI messages（原样）
	Model                 string
	MaxTokens             any // int / nil
	ReasoningEffort       string
	Temperature           any // float / nil
	TopP                  any
	TopK                  any // 仅 int 生效
	ContextLength         any // 仅 int 生效
	EnableThinking        any // bool / nil（nil = 按模型是否推理）
	PreserveThinking      bool
	ReasoningBudgetTokens any
	Tools                 []any
	ToolChoice            any
	ParallelToolCalls     any
}

// Event 引擎产出的一个事件：
//
//	{"type":"content"|"reasoning","text":str}
//	{"type":"tool_calls","delta":[...]}   OpenAI tool_calls 增量，原样透传
//	{"type":"usage","usage":dict}
//	{"type":"finish","reason":str}
//	{"type":"error","err":error}          流中错误（Python 生成器抛异常的对应物）
type Event struct {
	Type   string
	Text   string
	Delta  []any
	Usage  map[string]any
	Reason string
	Err    error
}

// ── 请求体构建（对齐 magpie qoderBody） ──────────────────────────────────────

var thinkTagRe = regexp.MustCompile(`</?think>`)

// stripThinkTags 剥掉内联进正文的 think 模板标签（断开历史回显污染链）。
func stripThinkTags(text string) string {
	return thinkTagRe.ReplaceAllString(text, "")
}

// textOf 从 OpenAI content 提取纯文本。
func textOf(content any) string {
	switch c := content.(type) {
	case string:
		return c
	case []any:
		var b strings.Builder
		for _, p := range c {
			if m, ok := p.(map[string]any); ok && m["type"] == "text" {
				if s, ok := m["text"].(string); ok {
					b.WriteString(s)
				}
			}
		}
		return b.String()
	}
	return ""
}

// contentBlocks OpenAI content → Qoder content blocks。
func contentBlocks(content any) []any {
	switch c := content.(type) {
	case string:
		if c == "" {
			return nil
		}
		return []any{map[string]any{"type": "text", "text": c}}
	case []any:
		blocks := []any{}
		for _, p := range c {
			m, ok := p.(map[string]any)
			if !ok {
				continue
			}
			switch m["type"] {
			case "text":
				if s, _ := m["text"].(string); s != "" {
					blocks = append(blocks, map[string]any{"type": "text", "text": s})
				}
			case "image_url":
				var urlStr string
				if u, ok := m["image_url"].(map[string]any); ok {
					urlStr, _ = u["url"].(string)
				} else if s, ok := m["image_url"].(string); ok {
					urlStr = s
				}
				if urlStr != "" {
					blocks = append(blocks, map[string]any{
						"type": "image_url", "image_url": map[string]any{"url": urlStr}})
				}
			}
		}
		return blocks
	}
	return nil
}

// qoderMessages 将 OpenAI messages 转为 Qoder 格式（跳过 system，保留 tool_calls / tool 结果）。
// 历史助手正文里的内联 think 标签剥掉，防止被污染的会话每轮回显；剥完只剩空白的
// text 块直接丢弃（如 "\n</think>\n\n" 整条变空）。
func qoderMessages(messages []any) []any {
	out := []any{}
	for _, mi := range messages {
		m, ok := mi.(map[string]any)
		if !ok {
			continue
		}
		role, _ := m["role"].(string)
		switch role {
		case "system", "developer":
			continue
		case "tool":
			out = append(out, map[string]any{
				"role":         "tool",
				"tool_call_id": m["tool_call_id"],
				"content":      contentBlocks(textOf(m["content"])),
			})
			continue
		}
		entry := map[string]any{"role": role, "content": contentBlocks(m["content"])}
		if role == "assistant" {
			// 历史助手正文里的内联 think 标签剥掉，防止被污染的会话每轮回显；
			// 剥完只剩空白的 text 块直接丢弃（如 "\n</think>\n\n" 整条变空）
			if blocks, ok := entry["content"].([]any); ok {
				stripped := []any{}
				for _, bi := range blocks {
					b, ok := bi.(map[string]any)
					if !ok {
						continue
					}
					s, _ := b["text"].(string)
					text := stripThinkTags(s)
					if strings.TrimSpace(text) != "" {
						stripped = append(stripped, map[string]any{"type": b["type"], "text": text})
					}
				}
				entry["content"] = stripped
			}
			// 客户端回传思考时原样带上（协议出站也叫 reasoning_content，不发明新字段）
			if rc, _ := m["reasoning_content"].(string); rc != "" {
				entry["reasoning_content"] = rc
			}
			if tcs, ok := m["tool_calls"].([]any); ok && len(tcs) > 0 {
				wire := []any{}
				for _, tci := range tcs {
					tc, ok := tci.(map[string]any)
					if !ok {
						continue
					}
					fn, _ := tc["function"].(map[string]any)
					name, args := "", ""
					if fn != nil {
						name, _ = fn["name"].(string)
						args, _ = fn["arguments"].(string)
					}
					ttype, _ := tc["type"].(string)
					if ttype == "" {
						ttype = "function"
					}
					wire = append(wire, map[string]any{
						"id":       tc["id"],
						"type":     ttype,
						"function": map[string]any{"name": name, "arguments": args},
					})
				}
				entry["tool_calls"] = wire
			}
		}
		contentLen := 0
		if bl, ok := entry["content"].([]any); ok {
			contentLen = len(bl)
		}
		if contentLen > 0 || entry["tool_calls"] != nil {
			out = append(out, entry)
		}
	}
	return out
}

// toolChoiceWire 返回要送出的 tool_choice（nil = 不送）。'none' 由调用方直接省略
// tools 表达。CLI 在 Qoder 路径上用 protobuf Value 包装（string→stringValue、
// object→structValue）；{type:"any"} 那套枚举属 Anthropic 适配器，此处不适用。
func toolChoiceWire(tc any) any {
	if s, ok := tc.(string); ok && (s == "auto" || s == "required") {
		return s
	}
	if m, ok := tc.(map[string]any); ok && m["type"] == "function" {
		return m
	}
	return nil
}

// BuildRequestBody 构建 agent_chat_generation 请求体（plaintext JSON），
// 返回编码后的 wire body。chat 是 OpenAI chat completion 请求形状的 map。
func (c *Client) BuildRequestBody(chat map[string]any, modelConfig map[string]any) (string, error) {
	messages, _ := chat["messages"].([]any)

	// 提取 system 消息
	var sysParts []string
	for _, mi := range messages {
		m, ok := mi.(map[string]any)
		if !ok {
			continue
		}
		if role, _ := m["role"].(string); role == "system" || role == "developer" {
			if t := textOf(m["content"]); t != "" {
				sysParts = append(sysParts, t)
			}
		}
	}
	systemText := strings.Join(sysParts, "\n\n")
	sysText := proto.QoderSys
	if systemText != "" {
		sysText += "\n\n" + systemText
	}
	sysBlock := map[string]any{"type": "text", "text": sysText}

	// 推理参数
	modelReq, _ := chat["model"].(string)
	if modelReq == "" {
		modelReq = "Auto"
	}
	reasoningEffort, _ := chat["reasoning_effort"].(string)
	maxTokens := any(32000)
	if v := chat["max_completion_tokens"]; v != nil && numOrZero(v) > 0 {
		maxTokens = int(numOrZero(v))
	} else if v := chat["max_tokens"]; v != nil && numOrZero(v) > 0 {
		maxTokens = int(numOrZero(v))
	}

	// 判断是否推理模型
	isReasoning := false
	if modelConfig != nil {
		isReasoning = boolOr(modelConfig["is_reasoning"])
		if tc, ok := modelConfig["thinking_config"].(map[string]any); ok && boolOr(tc["enabled"]) {
			isReasoning = true
		}
	}

	// 客户端可显式开关思考；未指定时按模型是否推理
	enableThinking := isReasoning
	if v, ok := chat["enable_thinking"]; ok {
		enableThinking, _ = v.(bool)
	}

	params := map[string]any{"enable_thinking": enableThinking, "max_tokens": maxTokens}
	if v := chat["temperature"]; v != nil {
		params["temperature"] = v
	}
	if v := chat["top_p"]; v != nil {
		params["top_p"] = v
	}
	// top_k 仅 int 生效（float 是客户端误传，直接丢）
	if _, ok := chat["top_k"].(float64); ok {
		if f, ok := chat["top_k"].(float64); ok && f == float64(int(f)) {
			params["top_k"] = int(f)
		}
	}
	if reasoningEffort != "" && enableThinking {
		params["reasoning_effort"] = reasoningEffort
	}
	// reasoning_budget_tokens：CLI 由 thinkingBudget 写入，且只在思考开启时生效
	if budget, ok := chat["reasoning_budget_tokens"].(float64); ok {
		if int(budget) > 0 && enableThinking {
			params["reasoning_budget_tokens"] = int(budget)
		}
	}
	if boolOr(chat["preserve_thinking"]) {
		params["preserve_thinking"] = true
	}
	// context_length：CLI 在有 contextWindow 时写 parameters.context_length
	if cl, ok := chat["context_length"].(float64); ok && int(cl) > 0 {
		params["context_length"] = int(cl)
	}
	// tool_choice：CLI 写在 parameters 里，非顶层
	if tc := toolChoiceWire(chat["tool_choice"]); tc != nil {
		params["tool_choice"] = tc
	}

	modelConfigOut := any(modelConfig)
	if modelConfigOut == nil {
		modelConfigOut = map[string]any{"key": modelReq}
	}

	body := map[string]any{
		"parameters": params,
		"business": map[string]any{
			"product":  "app",
			"version":  proto.CosyVersion,
			"type":     "agent",
			"id":       NewUUIDHex(),
			"name":     "qoder2api session",
			"begin_at": time.Now().UnixMilli(),
			"stage":    "start",
		},
		"agent_id":     "agent_common",
		"task_id":      "common",
		"session_type": "app",
		"model_config": modelConfigOut,
		"system":       []any{sysBlock},
		"messages":     append([]any{map[string]any{"role": "system", "content": []any{sysBlock}}}, qoderMessages(messages)...),
	}

	// tools（只收 type=function 且有 name；tool_choice=none 时直接省略 tools）
	tools, _ := chat["tools"].([]any)
	if len(tools) > 0 && chat["tool_choice"] != "none" {
		wireTools := []any{}
		for _, ti := range tools {
			t, ok := ti.(map[string]any)
			if !ok || t["type"] != "function" {
				continue
			}
			fn, _ := t["function"].(map[string]any)
			if fn == nil {
				continue
			}
			name, _ := fn["name"].(string)
			if name == "" {
				continue
			}
			desc, _ := fn["description"].(string)
			pars, ok := fn["parameters"]
			if !ok || pars == nil {
				pars = map[string]any{"type": "object", "properties": map[string]any{}}
			}
			wireTools = append(wireTools, map[string]any{
				"type": "function",
				"function": map[string]any{
					"name":        name,
					"description": desc,
					"parameters":  pars,
				},
			})
		}
		if len(wireTools) > 0 {
			body["tools"] = wireTools
		}
	}
	if ptc, ok := chat["parallel_tool_calls"].(bool); ok {
		params["parallel_tool_calls"] = ptc
	}

	plaintext, err := marshalCompact(body)
	if err != nil {
		return "", err
	}
	return QoderEncode(plaintext), nil
}

// ── ThinkSplitter ─────────────────────────────────────────────────────────────

// ThinkSplitter 跨 chunk 的 <think> 内联标签分流状态机。
//
// 背景：Qoder 上游偶发不走 reasoning_content 结构化通道，把推理模板
// <think>…</think>（有时只有孤立的闭合标签）内联在 delta.content 里；直接透传
// 会让客户端把标签当正文渲染并存进会话历史，之后每轮回显。
//
// 规则：<think> 后内容归 reasoning，</think> 后回到正文；无配对的孤立标签按
// 噪声丢弃；流尾可能跨 chunk 断开的残缺片段暂存，Flush 冲刷。
type ThinkSplitter struct {
	inThink bool
	tail    string
	pending []Seg
}

type Seg struct {
	Kind string // "content" | "reasoning"
	Text string
}

const (
	thinkOpen  = "<think>"
	thinkClose = "</think>"
	thinkHold  = len(thinkClose) - 1 // 可能是标签前缀的最长尾部片段
)

// Feed 喂入一段 content；产出通过 Drain 取用。
func (s *ThinkSplitter) Feed(text string) {
	buf := s.tail + text
	s.tail = ""
	var segs []Seg
	i := 0
	for i < len(buf) {
		o := strings.Index(buf[i:], thinkOpen)
		if o >= 0 {
			o += i
		}
		cl := strings.Index(buf[i:], thinkClose)
		if cl >= 0 {
			cl += i
		}
		var hit int
		var tag string
		var closing *bool
		if s.inThink {
			// think 段内：闭合标签翻出；再现的 <think> 是噪声，丢弃不翻状态
			if cl < 0 || (o >= 0 && o < cl) {
				hit, tag, closing = o, thinkOpen, nil
			} else {
				hit, tag, closing = cl, thinkClose, boolPtr(true)
			}
		} else {
			if o < 0 {
				hit, tag, closing = cl, thinkClose, boolPtr(true)
			} else if cl < 0 || o < cl {
				hit, tag, closing = o, thinkOpen, boolPtr(false)
			} else {
				hit, tag, closing = cl, thinkClose, boolPtr(true)
			}
		}
		if hit < 0 {
			// 无完整标签：仅暂存可能是标签前缀的尾部，其余按当前状态归属
			keep := 0
			max := thinkHold
			if max > len(buf)-i {
				max = len(buf) - i
			}
			for k := max; k > 0; k-- {
				seg := buf[len(buf)-k:]
				if strings.HasPrefix(thinkOpen, seg) || strings.HasPrefix(thinkClose, seg) {
					keep = k
					break
				}
			}
			if body := buf[i : len(buf)-keep]; body != "" {
				kind := "content"
				if s.inThink {
					kind = "reasoning"
				}
				segs = append(segs, Seg{Kind: kind, Text: body})
			}
			s.tail = buf[len(buf)-keep:]
			break
		}
		if body := buf[i:hit]; body != "" {
			kind := "content"
			if s.inThink {
				kind = "reasoning"
			}
			segs = append(segs, Seg{Kind: kind, Text: body})
		}
		// 配对的开关标签翻转状态；错配/嵌套的孤立标签按噪声丢弃
		if closing != nil && *closing == s.inThink {
			s.inThink = !s.inThink
		}
		i = hit + len(tag)
	}
	for _, sg := range segs {
		if n := len(s.pending); n > 0 && s.pending[n-1].Kind == sg.Kind {
			s.pending[n-1].Text += sg.Text
		} else {
			s.pending = append(s.pending, sg)
		}
	}
}

// Drain 取出已完成的有序段。
func (s *ThinkSplitter) Drain() []Seg {
	out := s.pending
	s.pending = nil
	return out
}

// Flush 流末冲刷：残留段 + 跨 chunk 的标签前缀尾巴。
func (s *ThinkSplitter) Flush() []Seg {
	out := s.pending
	s.pending = nil
	if s.tail != "" {
		kind := "content"
		if s.inThink {
			kind = "reasoning"
		}
		out = append(out, Seg{Kind: kind, Text: s.tail})
		s.tail = ""
	}
	return out
}

func boolPtr(b bool) *bool { return &b }

// ── COSY 推理调用 ─────────────────────────────────────────────────────────────

// RunQoderCosy 直接 COSY API 调用，产出事件流（信封解析 + <think> 分流）。
// 错误以 Event{Type:"error"} 交付（Python 生成器抛 UpstreamError 的对应物）；
// 10605 排队限流、流中断、401/403 reauthenticate 的重试决策在调用方（handler 层）。
func (c *Client) RunQoderCosy(p RunParams) iter.Seq[Event] {
	return func(yield func(Event) bool) {
		emit := func(ev Event) bool { return yield(ev) }
		fail := func(err error) bool { return emit(Event{Type: "error", Err: err}) }

		// 非限免模型直接拒（付费档会真扣额度）。路由层已挡过一遍，这里是纵深防御：
		// 引擎也可能被测试/脚本直接调用。
		model, err := c.EnsureFreeModel(p.Model)
		if err != nil {
			fail(err)
			return
		}
		modelConfig := c.FindModelConfig(model)

		chat := map[string]any{
			"messages": p.Messages,
			"model":    model,
			"stream":   true,
		}
		if p.MaxTokens != nil {
			chat["max_tokens"] = p.MaxTokens
		}
		if p.ReasoningEffort != "" {
			chat["reasoning_effort"] = p.ReasoningEffort
		}
		if p.Tools != nil {
			chat["tools"] = p.Tools
		}
		if p.ToolChoice != nil {
			chat["tool_choice"] = p.ToolChoice
		}
		if p.ParallelToolCalls != nil {
			chat["parallel_tool_calls"] = p.ParallelToolCalls
		}
		if p.Temperature != nil {
			chat["temperature"] = p.Temperature
		}
		if p.TopP != nil {
			chat["top_p"] = p.TopP
		}
		if p.TopK != nil {
			chat["top_k"] = p.TopK
		}
		if p.ContextLength != nil {
			chat["context_length"] = p.ContextLength
		}
		if p.EnableThinking != nil {
			chat["enable_thinking"] = p.EnableThinking
		}
		if p.PreserveThinking {
			chat["preserve_thinking"] = true
		}
		if p.ReasoningBudgetTokens != nil {
			chat["reasoning_budget_tokens"] = p.ReasoningBudgetTokens
		}

		wireBody, err := c.BuildRequestBody(chat, modelConfig)
		if err != nil {
			fail(upstreamErr(502, "构建请求体失败: %v", err))
			return
		}
		url := c.GatewayHost + proto.ChatPath + proto.ChatQuery

		// 签名头里的 date/blob 依赖身份，重读后要重签，所以整段放在重试循环内
		var resp *http.Response
		for attempt := 0; attempt < 2; attempt++ {
			cred, idErr := c.LoadIdentity(false)
			if idErr != nil {
				fail(upstreamErr(502, "身份不可用: %v", idErr))
				return
			}
			headers, err := BuildCosyHeaders(url, wireBody, cred, c.MachineID(cred), 0)
			if err != nil {
				fail(upstreamErr(502, "构建签名头失败: %v", err))
				return
			}
			headers["Accept"] = "text/event-stream"
			headers["Cache-Control"] = "no-cache"
			if modelConfig != nil {
				if k, _ := modelConfig["key"].(string); k != "" {
					headers["X-Model-Key"] = k
				} else {
					headers["X-Model-Key"] = model
				}
				if src, _ := modelConfig["source"].(string); src != "" {
					headers["X-Model-Source"] = src
				} else {
					headers["X-Model-Source"] = ""
				}
			}

			r, err := c.gatewayPostSSE(url, wireBody, headers)
			if err != nil {
				// 措辞与 Python requests.post 的包装一致（复用调用方的 _connect_wait 判据）
				fail(upstreamErr(502, "upstream request failed: %v", err))
				return
			}
			resp = r
			if resp.StatusCode == 401 || resp.StatusCode == 403 {
				snippet := readSnippet(resp.Body, 500)
				resp.Body.Close()
				// 10605 是业务排队限流，换凭证没用：不续期、不在这里重发，
				// 直接抛给调用方按 waitTime 睡等重试
				if strings.Contains(snippet, "10605") {
					fail(upstreamErr(resp.StatusCode, "%s", snippet))
					return
				}
				if attempt == 0 {
					c.Reauthenticate()
					continue
				}
				fail(upstreamErr(resp.StatusCode, "%s", snippet))
				return
			}
			break
		}
		if resp == nil {
			return
		}
		if resp.StatusCode != 200 {
			snippet := readSnippet(resp.Body, 500)
			resp.Body.Close()
			// 错误响应不是 SSE 流，可安全读取全文
			fail(upstreamErr(resp.StatusCode, "%s", snippet))
			return
		}
		bodyReadCloser := resp.Body
		defer bodyReadCloser.Close()

		// 上游对这两个 path 只回 SSE，没有 JSON 单体响应形态
		splitter := &ThinkSplitter{}
		sc := bufio.NewScanner(bodyReadCloser)
		sc.Buffer(make([]byte, 64*1024), 8*1024*1024)
		for sc.Scan() {
			line := sc.Text()
			if !strings.HasPrefix(line, "data:") {
				continue
			}
			payload := strings.TrimSpace(line[5:])
			if payload == "[DONE]" {
				break
			}
			var envelope map[string]any
			if jsonUnmarshal([]byte(payload), &envelope) != nil {
				continue
			}

			// 检查错误状态
			statusCode := intOr(envelope["statusCodeValue"])
			if statusCode != 0 && statusCode != 200 {
				inner := fmt.Sprint(envelope["body"])
				inner = truncStr(inner, 300)
				// 10605 是业务排队限流，凭证没问题：不续期，直接抛给调用方睡等重试
				if !(statusCode == 401 || statusCode == 403) || !strings.Contains(inner, "10605") {
					if statusCode == 401 || statusCode == 403 {
						c.Reauthenticate()
					}
				}
				fail(upstreamErr(statusCode, "上游错误: %s", inner))
				return
			}

			// body 是 OpenAI chunk 的 JSON 字符串（二次解码）
			bodyStr, _ := envelope["body"].(string)
			if bodyStr == "" {
				continue
			}
			var chunk map[string]any
			if jsonUnmarshal([]byte(bodyStr), &chunk) != nil {
				continue
			}

			choices, _ := chunk["choices"].([]any)
			if len(choices) == 0 {
				if usage, ok := chunk["usage"].(map[string]any); ok && usage != nil {
					if !emit(Event{Type: "usage", Usage: usage}) {
						return
					}
				}
				continue
			}
			choice, _ := choices[0].(map[string]any)
			if choice == nil {
				continue
			}
			delta, _ := choice["delta"].(map[string]any)

			// 推理内容
			if rc, _ := delta["reasoning_content"].(string); rc != "" {
				if !emit(Event{Type: "reasoning", Text: rc}) {
					return
				}
			}

			// 正文内容：经 <think> 分流（上游偶发把推理模板标签内联进 content，
			// 直接透传会被客户端当正文渲染并存进会话历史）
			if content, _ := delta["content"].(string); content != "" {
				splitter.Feed(content)
				for _, seg := range splitter.Drain() {
					if !emit(Event{Type: seg.Kind, Text: seg.Text}) {
						return
					}
				}
			}

			// tool calls：原样透传增量片段（客户端按 index 拼接 arguments）
			if tcs, ok := delta["tool_calls"].([]any); ok && len(tcs) > 0 {
				if !emit(Event{Type: "tool_calls", Delta: tcs}) {
					return
				}
			}

			if fr, _ := choice["finish_reason"].(string); fr != "" {
				if !emit(Event{Type: "finish", Reason: fr}) {
					return
				}
			}
		}
		if err := sc.Err(); err != nil {
			// 流正文阶段的传输层中断归一成 UpstreamError（调用方的「仅未产出字节时
			// 重试」判据才能看到它）
			fail(upstreamErr(502, "upstream request failed: %v", err))
			return
		}
		// 流尽：冲刷跨 chunk 残留的标签前缀
		for _, seg := range splitter.Flush() {
			if seg.Text != "" {
				if !emit(Event{Type: seg.Kind, Text: seg.Text}) {
					return
				}
			}
		}
	}
}

// gatewayPostSSE 带签名头打网关 POST（SSE 流）。超时语义对齐 requests 的
// timeout：只管「连接+拿到响应头」，SSE 长流不能被掐断——所以响应头超时
// 走 httpc() 的 Transport 配置，这里不设 ctx 截止。
func (c *Client) gatewayPostSSE(url, wireBody string, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(wireBody))
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return c.httpc().Do(req)
}

// readSnippet 读完错误响应 body（限 n 字节）。
func readSnippet(r io.ReadCloser, n int) string {
	if r == nil {
		return ""
	}
	defer r.Close()
	data, _ := io.ReadAll(io.LimitReader(r, int64(n)))
	return string(data)
}
