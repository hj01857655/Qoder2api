// Package handler 对应 Python 版 server.py + routes/：路由调度、鉴权、rid、
// in:/done: 日志、请求落盘。COSY 协议细节在 qoder 包，方言翻译在 adapters 包。
package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"qoder2api/internal/adapters"
	"qoder2api/internal/config"
	"qoder2api/internal/dump"
	"qoder2api/internal/qoder"
)

// Server 聚合全部依赖；Handler 挂到 http.ServeMux。
type Server struct {
	Cfg  *config.Config
	Q    *qoder.Client
	Dump *dump.Writer
	Log  *slog.Logger

	reqSeq atomic.Int64
}

// logMid 出 in: 行（对应 Python _log_request）。
func (s *Server) logMid(rid string, r *http.Request, payload map[string]any, bodyLen int) {
	ua := r.Header.Get("User-Agent")
	if ua == "" {
		ua = "-"
	}
	ua = strings.ReplaceAll(strings.ReplaceAll(ua, "\r", " "), "\n", " ")
	var msgs, tools int
	if l, ok := payload["messages"].([]any); ok {
		msgs = len(l)
	}
	if l, ok := payload["tools"].([]any); ok {
		tools = len(l)
	}
	stream := payload["stream"]
	s.Log.Info(rid+" in:",
		slog.String("line", fmt.Sprintf("%s %s | model=%s msgs=%d tools=%d stream=%v | ua=%s | body=%dB",
			r.Method, r.URL.Path, str(payload["model"]), msgs, tools, stream, ua, bodyLen)),
	)
}

// doneLog 出 done: 行（对应 Python _log_response / _stream_log 的收尾）。
func (s *Server) doneLog(rid, kind string, bytes int, t0 time.Time) {
	s.Log.Info(rid+" done:",
		slog.String("line", fmt.Sprintf("%s %dB %.1fs", kind, bytes, time.Since(t0).Seconds())),
	)
}

// nextRID 单调递增请求号（r%04d；进程内单调，dump 文件名带启动段防跨进程撞名）。
func (s *Server) nextRID() string {
	return fmt.Sprintf("r%04d", s.reqSeq.Add(1))
}

// Handler 组装路由。鉴权中间件包在最外层（/health 与面板例外）；
// 未注册路径与方法回 JSON 而非默认文本（Python errorhandler 404/405）。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.notFound) // 兜底：未注册路径 → JSON 404
	mux.HandleFunc("/health", s.health)
	mux.HandleFunc("/v1/models", s.models)
	mux.HandleFunc("/v1/chat/completions", s.chat)
	mux.HandleFunc("/v1/responses", s.responses)
	mux.HandleFunc("/v1/messages", s.anthropic)
	mux.HandleFunc("/v1/completions", s.completions)
	mux.HandleFunc("/login", s.login)
	mux.HandleFunc("/login/status", s.loginStatus)
	return s.auth(mux)
}

// auth 鉴权 + rid 分配 + in: 日志 + 请求落盘（对应 _check_auth / _log_request）。
func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := s.nextRID()
		t0 := time.Now()

		if s.Cfg.APIKey != "" && r.URL.Path != "/health" && r.URL.Path != "/" {
			auth := r.Header.Get("Authorization")
			token := ""
			if strings.HasPrefix(auth, "Bearer") {
				token = strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
			}
			if token != s.Cfg.APIKey {
				// 定位还在用旧 key 的客户端：记下来源与 UA
				masked := "(empty)"
				if token != "" {
					masked = token[:min(6, len(token))] + "…"
				}
				s.Log.Warn(rid+" 401 bad key",
					slog.String("line", fmt.Sprintf("%s %s | ip=%s UA=%s key=%s",
						r.Method, r.URL.Path, r.RemoteAddr, r.Header.Get("User-Agent"), masked)))
				writeJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]any{
					"message": "Invalid API key", "type": "invalid_request_error"}})
				return
			}
		}

		var payload map[string]any
		bodyLen := 0
		var rawBody []byte
		if r.Body != nil {
			rawBody, _ = io.ReadAll(io.LimitReader(r.Body, 64<<20))
			bodyLen = len(rawBody)
			if len(rawBody) > 0 {
				_ = json.Unmarshal(rawBody, &payload)
			}
		}
		s.logMid(rid, r, payload, bodyLen)
		// 请求原文落盘（可直接重放的纯 body，绝不落 header）
		s.Dump.Save(rid, "req", string(rawBody))

		ctx := withReqInfo(r.Context(), reqInfo{rid: rid, t0: t0, payload: payload})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "service": "Qoder2api"})
}

// notFound 未注册路径（Python _error_payload：/messages 路用 Anthropic 形状提示
// base URL 不含 /v1——多半是客户端把 base URL 填成了 .../v1）。
func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		writeJSON(w, http.StatusOK, map[string]any{
			"service": "Qoder2api",
			"endpoints": []string{
				"POST /v1/chat/completions", "POST /v1/completions", "POST /v1/responses",
				"POST /v1/messages", "GET /v1/models", "GET /health", "GET /login/status",
			},
		})
		return
	}
	msg := "Not Found: " + r.URL.Path
	if strings.Contains(r.URL.Path, "/messages") {
		msg += "（Anthropic 客户端 base URL 应填 host:port，不含 /v1）"
		writeJSON(w, http.StatusNotFound, adapters.AnthropicErrorBody("not_found_error", msg))
		return
	}
	writeJSON(w, http.StatusNotFound, map[string]any{"error": map[string]any{
		"message": msg, "type": "not_found_error"}})
}

// ── 请求上下文 ───────────────────────────────────────────────────────────────

type reqInfo struct {
	rid     string
	t0      time.Time
	payload map[string]any
}

type reqInfoKey struct{}

func withReqInfo(ctx context.Context, info reqInfo) context.Context {
	return context.WithValue(ctx, reqInfoKey{}, info)
}

func reqInfoFrom(r *http.Request) reqInfo {
	info, _ := r.Context().Value(reqInfoKey{}).(reqInfo)
	return info
}

// ── 响应辅助 ─────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(marshalCompact(v))
}

// marshalCompact JSON 紧凑序列化，不转义 HTML 字符（中文/标签原样输出）。
func marshalCompact(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return []byte("null")
	}
	return bytes.TrimRight(buf.Bytes(), "\n")
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// sseHeaders 流式响应头（Cache-Control/X-Accel-Buffering 与 Python 版一致）。
func sseHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
}

// streamLog 包裹 SSE 行流：TTFT、字节数、原文落盘、done/断开日志
// （对应 Python _stream_log）。
func (s *Server) streamLog(seq iter.Seq[string], rid string, t0 time.Time) iter.Seq[string] {
	return func(yield func(string) bool) {
		total, ttft, seen := 0, time.Duration(0), 0
		var buf []string
		for line := range seq {
			seen++
			if seen == 1 {
				ttft = time.Since(t0)
			}
			total += len(line)
			buf = append(buf, line)
			if !yield(line) {
				s.Log.Warn(rid + " client 断开")
				s.Log.Info(rid+" done:",
					slog.String("line", fmt.Sprintf("stream %dB %.1fs ttft=%.1fs（断开）",
						total, time.Since(t0).Seconds(), ttft.Seconds())))
				return
			}
		}
		s.Dump.Save(rid, "resp", strings.Join(buf, ""))
		s.Log.Info(rid+" done:",
			slog.String("line", fmt.Sprintf("stream %dB %.1fs ttft=%.1fs",
				total, time.Since(t0).Seconds(), ttft.Seconds())))
	}
}

// writeSSE 把行流写给客户端（带流日志）。
func (s *Server) writeSSE(w http.ResponseWriter, r *http.Request, seq iter.Seq[string]) {
	sseHeaders(w)
	flusher, _ := w.(http.Flusher)
	for line := range s.streamLog(seq, reqInfoFrom(r).rid, reqInfoFrom(r).t0) {
		if _, err := io.WriteString(w, line); err != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}

// ── 日志：request.log 2MB×3 轮转 + stdout（与 Python RotatingFileHandler 对齐）──

// NewLogger 建 slog logger：同时写 stdout 与 request.log（2MB 轮转，保 3 份）。
func NewLogger(stateDir string) *slog.Logger {
	path := filepath.Join(stateDir, "request.log")
	rw := &rotateWriter{path: path, maxBytes: 2 << 20, backupCount: 3}
	return slog.New(slog.NewTextHandler(io.MultiWriter(os.Stdout, rw), nil))
}

type rotateWriter struct {
	mu          sync.Mutex
	path        string
	maxBytes    int64
	backupCount int
	f           *os.File
	written     int64
}

func (rw *rotateWriter) Write(p []byte) (int, error) {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	if rw.f == nil {
		if err := rw.open(); err != nil {
			return 0, err
		}
	}
	if rw.written+int64(len(p)) > rw.maxBytes {
		rw.rotate()
	}
	n, err := rw.f.Write(p)
	rw.written += int64(n)
	return n, err
}

func (rw *rotateWriter) open() error {
	f, err := os.OpenFile(rw.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	rw.f = f
	if info, err := f.Stat(); err == nil {
		rw.written = info.Size()
	}
	return nil
}

// rotate 关闭当前文件，.log.(n-1) → .log.n 链式改名，重开新文件。
func (rw *rotateWriter) rotate() {
	if rw.f != nil {
		rw.f.Close()
		rw.f = nil
	}
	for i := rw.backupCount - 1; i > 0; i-- {
		os.Rename(fmt.Sprintf("%s.%d", rw.path, i), fmt.Sprintf("%s.%d", rw.path, i+1))
	}
	os.Rename(rw.path, rw.path+".1")
	rw.written = 0
	_ = rw.open()
}
