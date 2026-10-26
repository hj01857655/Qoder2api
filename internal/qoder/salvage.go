// Package qoder 的 antml 文本工具调用回收，对应 Python adapters/responses.py
// 的 InvokeSalvage：Qwen 系模型在部分系统提示下会把工具调用写成 antml 纯文本
// 而不是结构化 tool_calls：
//
//	<invoke name="Bash">
//	<parameter name="command">…
//	<parameter name="timeout">600000
//	</invoke>
//
// 客户端（claude-cli / grok / deepseek-harness）只认结构化 tool_calls，文本透传
// 会直接卡死回合（finish=stop、无工具调用）。回收器无副作用：解析失败一律降级
// 为纯文本透传，绝不丢内容。
package qoder

import (
	"encoding/json"
	"regexp"
	"strings"
)

const (
	invokeStart = `<invoke name="`
	invokeEnd   = `</invoke>`
)

// openParamRe 参数开标签。Go regexp 不支持反向引用，闭标签 </parameter> 用
// strings.Index 手工配对（见 parseInvoke）。
var openParamRe = regexp.MustCompile(`<(\w+) name="([^"]*)">`)

// SalvEvent 回收产出："text" 透传正文，"tool_call" 拆回结构化调用。
type SalvEvent struct {
	Kind   string // "text" | "tool_call"
	Text   string
	Name   string
	Params map[string]any
}

// InvokeSalvage 正文文本工具调用的流式回收器（有界前瞻 ≤14 字符）。
type InvokeSalvage struct{ buf string }

// coerceParam XML 参数值是裸文本：数字/布尔还原成 JSON 类型（如 timeout 600000），
// 其余保持字符串。
func coerceParam(v string) any {
	var x any
	if json.Unmarshal([]byte(v), &x) == nil {
		switch x.(type) {
		case float64, bool:
			return x
		}
	}
	return v
}

// Feed 喂入一段正文。只扣住「可能是 invoke 起始标记」的缓冲尾部（≤14 字符），
// 其余正文实时放行。
func (s *InvokeSalvage) Feed(text string) []SalvEvent {
	if text == "" {
		return nil
	}
	var out []SalvEvent
	s.buf += text
	for {
		start := strings.Index(s.buf, invokeStart)
		if start == -1 {
			hold := s.partialTail()
			cut := len(s.buf) - hold
			if head := s.buf[:cut]; head != "" {
				out = append(out, SalvEvent{Kind: "text", Text: head})
			}
			s.buf = s.buf[cut:]
			return out
		}
		end := strings.Index(s.buf[start:], invokeEnd)
		if end == -1 {
			// 块未闭合：放行标记前文本，从标记起扣住
			if start > 0 {
				out = append(out, SalvEvent{Kind: "text", Text: s.buf[:start]})
			}
			s.buf = s.buf[start:]
			return out
		}
		end += start
		// 完整块：前段放行、解析块、继续扫剩余
		if start > 0 {
			out = append(out, SalvEvent{Kind: "text", Text: s.buf[:start]})
		}
		block := s.buf[start : end+len(invokeEnd)]
		if tc := parseInvoke(block); tc != nil {
			out = append(out, *tc)
		} else {
			out = append(out, SalvEvent{Kind: "text", Text: block}) // 解析失败：整块降级纯文本
		}
		s.buf = s.buf[end+len(invokeEnd):]
	}
}

// Flush 流末清空残留缓冲（未闭合块退回纯文本）。
func (s *InvokeSalvage) Flush() []SalvEvent {
	if s.buf == "" {
		return nil
	}
	out := []SalvEvent{{Kind: "text", Text: s.buf}}
	s.buf = ""
	return out
}

// partialTail 缓冲尾部是起始标记部分前缀的字符数（0 = 无）。
func (s *InvokeSalvage) partialTail() int {
	max := len(s.buf)
	if max > len(invokeStart) {
		max = len(invokeStart)
	}
	for n := max; n > 0; n-- {
		if strings.HasSuffix(s.buf, invokeStart[:n]) {
			return n
		}
	}
	return 0
}

// parseInvoke 解析完整 invoke 块 → tool_call；失败返回 nil。
func parseInvoke(block string) *SalvEvent {
	nameRe := regexp.MustCompile(`^<invoke name="([^"]+)">\s*`)
	m := nameRe.FindStringSubmatch(block)
	if m == nil {
		return nil
	}
	inner := block[len(m[0]) : len(block)-len(invokeEnd)]
	params := map[string]any{}
	for _, pm := range openParamRe.FindAllStringSubmatchIndex(inner, -1) {
		tag := inner[pm[2]:pm[3]]
		if tag != "parameter" {
			continue
		}
		closeTag := "</" + tag + ">"
		start := pm[1]
		idx := strings.Index(inner[start:], closeTag)
		if idx == -1 {
			continue
		}
		params[inner[pm[4]:pm[5]]] = coerceParam(inner[start : start+idx])
	}
	return &SalvEvent{Kind: "tool_call", Name: m[1], Params: params}
}

// ContainsInvokeStart 判断缓冲里是否有未降级的 invoke 起始（流尾日志用）。
func ContainsInvokeStart(s string) bool { return strings.Contains(s, invokeStart) }
