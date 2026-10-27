// golden_test.go — handler 层端到端验证（httptest 假上游，绝不连真实 Qoder 网关）。
// 假上游只覆盖两条 COSY 端点：模型清单与 agent_chat_generation SSE 信封；
// 签名/AES/RSA 都是本地运算，不需要真网关。断言对齐 Python 版语义：
//  1. chat 流式：<think> 分流、role 首帧、include_usage、[DONE]
//  2. chat 非流式：usage 兜底 0（DeepSeek-Flash 不发 usage 的对应物）
//  3. 模型门禁：收费/未知模型 400 model_not_allowed
//  4. 信封 statusCodeValue≠200：错误透传（流式 error 帧 / 非流式状态码）
//  5. 10605 排队限流：waitTime 睡等后重试成功
//  6. antml 文本工具调用回收 → 结构化 tool_calls + finish=tool_calls
//  7. /v1/models 只出限免
package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"qoder2api/internal/config"
	"qoder2api/internal/dump"
	"qoder2api/internal/qoder"
)

const usageJSON = `{"prompt_tokens":10,"completion_tokens":7,"total_tokens":17,
"completion_tokens_details":{"reasoning_tokens":3},"prompt_tokens_details":{"cached_tokens":0}}`

// ── 假上游 ───────────────────────────────────────────────────────────────────

type fakeUpstream struct {
	t    *testing.T
	mode string // "stream" | "nousage" | "err-env" | "rate" | "salvage"

	mu       sync.Mutex
	chatReq  map[string]any // 最近一次收到的网关请求体
	chatN    int            // 收到的 chat 请求数
	modelReq int
}

func sseLine(obj any) string {
	raw, _ := json.Marshal(obj)
	return "data: " + string(raw) + "\n\n"
}

// env COSY 信封：body 是 OpenAI chunk 的 JSON **字符串**（二次解码）。
func env(chunk any) string {
	inner, _ := json.Marshal(chunk)
	outer, _ := json.Marshal(map[string]any{"statusCodeValue": 200, "body": string(inner)})
	return "data: " + string(outer) + "\n\n"
}

func chunkLine(delta map[string]any, finish any) string {
	return env(map[string]any{
		"id": "c1", "object": "chat.completion.chunk", "created": 1, "model": "m",
		"choices": []any{map[string]any{"index": 0, "delta": delta, "finish_reason": finish}},
	})
}

func usageLine() string {
	return env(map[string]any{
		"id": "c1", "object": "chat.completion.chunk", "created": 1, "model": "m",
		"choices": []any{}, "usage": json.RawMessage(usageJSON),
	})
}

func (f *fakeUpstream) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/algo/api/v2/model/list", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.modelReq++
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"chat":[
			{"key":"Qwen3.8-Flash","display_name":"Qwen3.8-Flash","enable":true,
			 "is_reasoning":false,"max_input_tokens":128000,
			 "price_factor":0.0,"is_free":true,"original_price_factor":0.1},
			{"key":"DeepSeek-Flash","display_name":"DeepSeek-Flash","enable":true,
			 "is_reasoning":true,"max_input_tokens":128000,
			 "price_factor":0.0,"is_free":true},
			{"key":"Paid-Model","display_name":"Paid-Model","enable":true,
			 "price_factor":1.0}
		]}`))
	})
	mux.HandleFunc("/algo/api/v2/service/pro/sse/agent_chat_generation", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.chatN++
		f.chatReq = nil
		// wire body 是 QoderEncode 过的（Python 同款：data=wire_body），先解码再看 JSON
		raw, _ := io.ReadAll(r.Body)
		if plain, err := qoder.QoderDecode(string(raw)); err == nil {
			var m map[string]any
			if json.Unmarshal(plain, &m) == nil {
				f.chatReq = m
			}
		}
		n := f.chatN
		mode := f.mode
		f.mu.Unlock()

		w.Header().Set("Content-Type", "text/event-stream")
		switch mode {
		case "err-env":
			inner, _ := json.Marshal(map[string]any{"message": "boom"})
			fmt.Fprint(w, sseLine(map[string]any{"statusCodeValue": 500, "body": string(inner)}))
			fmt.Fprint(w, "data: [DONE]\n\n")
		case "rate":
			if n == 1 {
				inner := `{"code":"10605","waitTime":1,"message":"queued"}`
				fmt.Fprint(w, sseLine(map[string]any{"statusCodeValue": 403, "body": inner}))
				fmt.Fprint(w, "data: [DONE]\n\n")
				return
			}
			fallthrough
		case "salvage":
			if mode == "salvage" {
				fmt.Fprint(w, chunkLine(map[string]any{"role": "assistant", "content": "前文"}, nil))
				fmt.Fprint(w, chunkLine(map[string]any{
					"content": "<invoke name=\"get_weather\">\n<parameter name=\"city\">BJ</parameter>\n</invoke>"}, nil))
				fmt.Fprint(w, chunkLine(map[string]any{}, "stop"))
				fmt.Fprint(w, "data: [DONE]\n\n")
				return
			}
			fallthrough
		case "nousage":
			fmt.Fprint(w, chunkLine(map[string]any{"role": "assistant", "content": "<think>abc</think>"}, nil))
			fmt.Fprint(w, chunkLine(map[string]any{"content": "hi"}, nil))
			fmt.Fprint(w, chunkLine(map[string]any{}, "stop"))
			fmt.Fprint(w, "data: [DONE]\n\n")
		default: // "stream"
			fmt.Fprint(w, chunkLine(map[string]any{"role": "assistant", "content": "<think>abc</think>"}, nil))
			fmt.Fprint(w, chunkLine(map[string]any{"content": "hi"}, nil))
			fmt.Fprint(w, usageLine())
			fmt.Fprint(w, chunkLine(map[string]any{}, "stop"))
			fmt.Fprint(w, "data: [DONE]\n\n")
		}
	})
	return mux
}

// ── 装配 ─────────────────────────────────────────────────────────────────────

func newTestServer(t *testing.T, mode string, apiKey string) (*Server, *fakeUpstream) {
	t.Helper()
	fake := &fakeUpstream{t: t, mode: mode}
	upSrv := httptest.NewServer(fake.handler())
	t.Cleanup(upSrv.Close)

	stateDir := t.TempDir()
	// 短 token（<24 字符，避免输出管道替换占位符）；expire_time 在未来，免触发续期
	creds := fmt.Sprintf(`{"access_token":"jt-local","token_type":"job",
"expire_time":%d,"uid":"u1","name":"tester","machine_id":"mid-1"}`,
		time.Now().Add(time.Hour).Unix())
	if err := os.WriteFile(filepath.Join(stateDir, "credentials.json"), []byte(creds), 0o600); err != nil {
		t.Fatal(err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	q := &qoder.Client{
		OpenAPIHost: upSrv.URL, WebHost: upSrv.URL, GatewayHost: upSrv.URL,
		CredPath: filepath.Join(stateDir, "credentials.json"),
		Persist:  false, Timeout: 15 * time.Second, Log: log,
	}
	cfg := &config.Config{StateDir: stateDir}
	srv := &Server{
		Cfg:  cfg,
		Q:    q,
		Dump: dump.New(false, stateDir, 10),
		Log:  log,
	}
	if apiKey != "" {
		cfg.APIKey = apiKey
	}
	return srv, fake
}

func postJSON(t *testing.T, h http.Handler, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// parseFrames SSE data: 帧 → JSON 对象列表（跳过注释行与 [DONE]）。
func parseFrames(t *testing.T, raw string) []map[string]any {
	t.Helper()
	var events []map[string]any
	for _, block := range strings.Split(raw, "\n\n") {
		block = strings.TrimSpace(block)
		if !strings.HasPrefix(block, "data:") || strings.TrimSpace(block[5:]) == "[DONE]" {
			continue
		}
		var ev map[string]any
		if err := json.Unmarshal([]byte(strings.TrimSpace(block[5:])), &ev); err != nil {
			t.Fatalf("帧解析失败: %v\n%s", err, block)
		}
		events = append(events, ev)
	}
	return events
}

const chatReqFmt = `{"model":%q,"stream":%s,"messages":[{"role":"user","content":"hi"}],
"stream_options":{"include_usage":true}}`

// ── 用例 ─────────────────────────────────────────────────────────────────────

func TestChatStreamThinkAndUsage(t *testing.T) {
	srv, fake := newTestServer(t, "stream", "")
	rec := postJSON(t, srv.Handler(), "/v1/chat/completions", fmt.Sprintf(chatReqFmt, "Qwen3.8-Flash", "true"))
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("Content-Type=%s", ct)
	}

	fake.mu.Lock()
	req := fake.chatReq
	fake.mu.Unlock()
	if req == nil {
		t.Fatal("上游未收到请求体")
	}
	if _, ok := req["business"].(map[string]any); !ok {
		t.Fatalf("请求体缺 business 块: %v", req)
	}
	msgs, _ := req["messages"].([]any)
	if len(msgs) < 2 {
		t.Fatalf("messages=%v", msgs)
	}

	events := parseFrames(t, rec.Body.String())
	if len(events) < 3 {
		t.Fatalf("帧数不足: %d", len(events))
	}
	// 首帧带 role
	firstDelta := events[0]["choices"].([]any)[0].(map[string]any)["delta"].(map[string]any)
	if firstDelta["role"] != "assistant" {
		t.Fatalf("首帧 delta=%v", firstDelta)
	}
	// <think> 分流：reasoning_content 与 content 分开
	var reasoning, content string
	var usageFrame, finalFrame map[string]any
	for _, e := range events {
		chs := e["choices"].([]any)
		if len(chs) == 0 {
			usageFrame = e
			continue
		}
		choice := chs[0].(map[string]any)
		delta, _ := choice["delta"].(map[string]any)
		if delta == nil {
			continue
		}
		if rc, _ := delta["reasoning_content"].(string); rc != "" {
			reasoning += rc
		}
		if c, _ := delta["content"].(string); c != "" {
			content += c
		}
		if fr, _ := choice["finish_reason"].(string); fr != "" {
			finalFrame = e
		}
	}
	if reasoning != "abc" {
		t.Fatalf("reasoning=%q", reasoning)
	}
	if content != "hi" {
		t.Fatalf("content=%q", content)
	}
	if finalFrame == nil {
		t.Fatal("缺 finish 帧")
	}
	if usageFrame == nil {
		t.Fatal("缺 usage 帧（include_usage）")
	}
	if u := usageFrame["usage"].(map[string]any); u["total_tokens"] != float64(17) {
		t.Fatalf("usage=%v", u)
	}
	if !strings.HasSuffix(rec.Body.String(), "data: [DONE]\n\n") {
		t.Fatalf("结尾=%q", rec.Body.String()[max(0, rec.Body.Len()-40):])
	}
}

func TestChatNonStreamUsageFallback(t *testing.T) {
	// 上游不发 usage（DeepSeek-Flash 实测行为）→ 兜底全 0，不能是 null
	srv, _ := newTestServer(t, "nousage", "")
	rec := postJSON(t, srv.Handler(), "/v1/chat/completions", fmt.Sprintf(chatReqFmt, "DeepSeek-Flash", "false"))
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	choice := out["choices"].([]any)[0].(map[string]any)
	msg := choice["message"].(map[string]any)
	if msg["content"] != "hi" {
		t.Fatalf("content=%v", msg["content"])
	}
	if msg["reasoning_content"] != "abc" {
		t.Fatalf("reasoning_content=%v", msg["reasoning_content"])
	}
	if choice["finish_reason"] != "stop" {
		t.Fatalf("finish_reason=%v", choice["finish_reason"])
	}
	u := out["usage"].(map[string]any)
	for _, k := range []string{"prompt_tokens", "completion_tokens", "total_tokens"} {
		if u[k] != float64(0) {
			t.Fatalf("usage.%s=%v（应兜底 0）", k, u[k])
		}
	}
}

func TestModelGate(t *testing.T) {
	srv, _ := newTestServer(t, "stream", "")
	h := srv.Handler()

	rec := postJSON(t, h, "/v1/chat/completions", fmt.Sprintf(chatReqFmt, "Paid-Model", "false"))
	if rec.Code != 400 {
		t.Fatalf("收费模型 status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	e := out["error"].(map[string]any)
	if e["code"] != "model_not_allowed" {
		t.Fatalf("code=%v", e["code"])
	}
	if !strings.Contains(e["message"].(string), "不在限免范围") {
		t.Fatalf("message=%v", e["message"])
	}

	rec2 := postJSON(t, h, "/v1/chat/completions", fmt.Sprintf(chatReqFmt, "No-Such-Model", "false"))
	if rec2.Code != 400 || !strings.Contains(rec2.Body.String(), "未知模型") {
		t.Fatalf("未知模型 status=%d body=%s", rec2.Code, rec2.Body.String())
	}

	// 空模型归一默认档，放行
	rec3 := postJSON(t, h, "/v1/chat/completions",
		`{"stream":false,"messages":[{"role":"user","content":"hi"}]}`)
	if rec3.Code != 200 {
		t.Fatalf("空模型 status=%d body=%s", rec3.Code, rec3.Body.String())
	}
}

func TestModelsRoute(t *testing.T) {
	srv, _ := newTestServer(t, "stream", "")
	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d", rec.Code)
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	list := out["data"].([]any)
	if len(list) != 2 {
		t.Fatalf("限免模型应只有 2 个: %v", out)
	}
	for _, m := range list {
		item := m.(map[string]any)
		if item["is_free"] != true {
			t.Fatalf("非限免混入: %v", item)
		}
	}
}

func TestUpstreamEnvelopeError(t *testing.T) {
	// 流式：error 帧 + [DONE]
	srv, _ := newTestServer(t, "err-env", "")
	rec := postJSON(t, srv.Handler(), "/v1/chat/completions", fmt.Sprintf(chatReqFmt, "Qwen3.8-Flash", "true"))
	if rec.Code != 200 {
		t.Fatalf("流式 status=%d（SSE 已开始，状态码不可变）", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "boom") || !strings.Contains(rec.Body.String(), "[DONE]") {
		t.Fatalf("body=%s", rec.Body.String())
	}

	// 非流式：状态码透传 500
	srv2, _ := newTestServer(t, "err-env", "")
	rec2 := postJSON(t, srv2.Handler(), "/v1/chat/completions", fmt.Sprintf(chatReqFmt, "Qwen3.8-Flash", "false"))
	if rec2.Code != 500 {
		t.Fatalf("非流式 status=%d body=%s", rec2.Code, rec2.Body.String())
	}
	if !strings.Contains(rec2.Body.String(), "boom") {
		t.Fatalf("body=%s", rec2.Body.String())
	}
}

func TestRateLimitRetry10605(t *testing.T) {
	srv, fake := newTestServer(t, "rate", "")
	rec := postJSON(t, srv.Handler(), "/v1/chat/completions", fmt.Sprintf(chatReqFmt, "Qwen3.8-Flash", "false"))
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	fake.mu.Lock()
	n := fake.chatN
	fake.mu.Unlock()
	if n != 2 {
		t.Fatalf("chat 请求数=%d（应重试到第 2 次成功）", n)
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	msg := out["choices"].([]any)[0].(map[string]any)["message"].(map[string]any)
	if msg["content"] != "hi" {
		t.Fatalf("content=%v", msg["content"])
	}
}

func TestAntmlSalvageStream(t *testing.T) {
	srv, _ := newTestServer(t, "salvage", "")
	body := `{"model":"Qwen3.8-Flash","stream":true,
"messages":[{"role":"user","content":"weather?"}],
"tools":[{"type":"function","function":{"name":"get_weather",
"parameters":{"type":"object","properties":{"city":{"type":"string"}}}}}]}`
	rec := postJSON(t, srv.Handler(), "/v1/chat/completions", body)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var sawCall, sawText bool
	var finish string
	for _, e := range parseFrames(t, rec.Body.String()) {
		chs := e["choices"].([]any)
		if len(chs) == 0 {
			continue
		}
		choice := chs[0].(map[string]any)
		delta, _ := choice["delta"].(map[string]any)
		if delta == nil {
			continue
		}
		if tcs, ok := delta["tool_calls"].([]any); ok && len(tcs) > 0 {
			tc := tcs[0].(map[string]any)
			fn := tc["function"].(map[string]any)
			if fn["name"] != "get_weather" || fn["arguments"] != `{"city":"BJ"}` {
				t.Fatalf("tool_call=%v", fn)
			}
			sawCall = true
		}
		if c, _ := delta["content"].(string); strings.Contains(c, "前文") {
			sawText = true
		}
		if fr, _ := choice["finish_reason"].(string); fr != "" {
			finish = fr
		}
	}
	if !sawCall || !sawText {
		t.Fatalf("sawCall=%v sawText=%v", sawCall, sawText)
	}
	if finish != "tool_calls" {
		t.Fatalf("finish_reason=%q（回收后应为 tool_calls）", finish)
	}
}

func TestCompletionsRoute(t *testing.T) {
	srv, _ := newTestServer(t, "stream", "")
	rec := postJSON(t, srv.Handler(), "/v1/completions",
		`{"model":"Qwen3.8-Flash","stream":true,"prompt":"hi"}`)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "text_completion_chunk") {
		t.Fatalf("body=%s", rec.Body.String())
	}
	// reasoning 不外泄
	if strings.Contains(rec.Body.String(), "abc") {
		t.Fatalf("reasoning 泄漏进补全: %s", rec.Body.String())
	}
}

func TestAuthRequired(t *testing.T) {
	srv, _ := newTestServer(t, "stream", "k-local")
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != 401 || !strings.Contains(rec.Body.String(), "Invalid API key") {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader("{}"))
	req2.Header.Set("Authorization", "Bearer k-local")
	rec2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec2, req2)
	if rec2.Code == 401 {
		t.Fatalf("带 key 仍 401: %s", rec2.Body.String())
	}
}

func TestAdminOverviewAndPanel(t *testing.T) {
	srv, _ := newTestServer(t, "stream", "")
	h := srv.Handler()

	// 概览：凭据来自测试装配写好的 credentials.json；模型列表与 /v1/models 同源
	req := httptest.NewRequest(http.MethodGet, "/admin/api/overview", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	c := out["credential"].(map[string]any)
	if c["valid"] != true {
		t.Fatalf("credential=%v", c)
	}
	models, _ := out["models"].([]any)
	if len(models) != 2 {
		t.Fatalf("限免模型应 2 个: %v", out)
	}
	if out["local_auth"] != false {
		t.Fatalf("local_auth=%v", out["local_auth"])
	}

	// 面板页：内置版兜底
	req2 := httptest.NewRequest(http.MethodGet, "/admin", nil)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != 200 || !strings.Contains(rec2.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("status=%d ct=%s", rec2.Code, rec2.Header().Get("Content-Type"))
	}

	// 开 API_KEY 后：/admin 页面免鉴权（否则浏览器打不开面板），数据接口照常 401
	srv2, _ := newTestServer(t, "stream", "k-local")
	h2 := srv2.Handler()
	rec3 := httptest.NewRecorder()
	h2.ServeHTTP(rec3, httptest.NewRequest(http.MethodGet, "/admin", nil))
	if rec3.Code != 200 {
		t.Fatalf("/admin 应免鉴权 status=%d", rec3.Code)
	}
	rec4 := httptest.NewRecorder()
	h2.ServeHTTP(rec4, httptest.NewRequest(http.MethodGet, "/admin/api/overview", nil))
	if rec4.Code != 401 {
		t.Fatalf("/admin/api/overview 应 401 status=%d", rec4.Code)
	}
}

func TestNotFoundShape(t *testing.T) {
	srv, _ := newTestServer(t, "stream", "")
	// /v1/messages 误加 /v1 前缀的提示走 Anthropic 错误形状
	rec := postJSON(t, srv.Handler(), "/v1/v1/messages", "{}")
	if rec.Code != 404 || !strings.Contains(rec.Body.String(), "not_found_error") {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "base URL") {
		t.Fatalf("缺 base URL 提示: %s", rec.Body.String())
	}
}
