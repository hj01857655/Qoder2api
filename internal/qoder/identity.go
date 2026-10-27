// Package qoder 的身份与凭证：credentials.json 加载/原子保存、双 token 族续期
// （job ← jrt- 2 天、device ← drt- 30 天，两套刷新口不能互顶）、PKCE device flow
// 登录。对应 Python 版 lanes/qoder_cosy.py 的身份段 + oauth.py。
//
// token_type="job" 时 jobToken 响应的 jrt- 只活 2 天，**不能覆盖** refresh_token
// 里的 drt-（30 天/1 年长效登录态）——顶掉之后 2 天内就再也刷不回来，要重新走
// 浏览器授权。所以 job 族的刷新凭据单独存 job_refresh_token。
package qoder

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"qoder2api/internal/proto"
)

// NowUnix 秒级时间戳（便于测试注入的地方统一走这里）。
func NowUnix() int64 { return time.Now().Unix() }

// NewUUID 随机 UUIDv4 字符串。
func NewUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "00000000-0000-4000-8000-000000000000"
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// NewUUIDHex 随机 uuid4().hex（32 位无连字符）。
func NewUUIDHex() string { return strings.ReplaceAll(NewUUID(), "-", "") }

// Credentials credentials.json 的形状（Python dict 直读直写，字段与原版一致）。
type Credentials struct {
	Source                    string `json:"source,omitempty"`
	MachineID                 string `json:"machine_id,omitempty"`
	TokenType                 string `json:"token_type,omitempty"`
	SecurityOauthToken        string `json:"security_oauth_token,omitempty"`
	AccessToken               string `json:"access_token,omitempty"`
	RefreshToken              string `json:"refresh_token,omitempty"`
	JobRefreshToken           string `json:"job_refresh_token,omitempty"`
	ExpireTime                int64  `json:"expire_time,omitempty"`
	RefreshTokenExpireTime    int64  `json:"refresh_token_expire_time,omitempty"`
	JobRefreshTokenExpireTime int64  `json:"job_refresh_token_expire_time,omitempty"`
	UID                       string `json:"uid,omitempty"`
	Name                      string `json:"name,omitempty"`
	Email                     string `json:"email,omitempty"`
}

// UpstreamError 上游返回非 200 / 请求失败，携带可透传给客户端的 HTTP 状态码。
type UpstreamError struct {
	Status  int
	Message string
}

func (e *UpstreamError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.Status, e.Message) }

// ModelNotAllowedError 模型不在限免范围 / 未知模型 —— 本地判定，根本没发上游请求。
// message 原样给客户端（不带 "HTTP 400:" 前缀）。
type ModelNotAllowedError struct{ Message string }

func (e *ModelNotAllowedError) Error() string { return e.Message }
func (e *ModelNotAllowedError) Unwrap() error { return &UpstreamError{Status: 400, Message: e.Message} }

// 错误辅助：与 Python UpstreamError.__init__ 的消息格式一致。
func upstreamErr(status int, format string, a ...any) *UpstreamError {
	return &UpstreamError{Status: status, Message: fmt.Sprintf(format, a...)}
}

const (
	refreshLeadS    = 300 // 距到期不足 5min 先刷再发（magpie REFRESH_LEAD）
	signInTimeoutS  = 900 // device flow 等待授权
	signInPollS     = 2
	openapiRetryS   = 1 // openapi 偶发 TLS 抖动（实测 UNEXPECTED_EOF 后重试即通）
	openapiTimeoutS = 15
)

// Client COSY 协议客户端：身份缓存 + 凭证文件 + 上游/开放 API 端点。
// 端点字段是导出的：测试把 Gateway/OpenAPI 指到 httptest 假上游。
type Client struct {
	OpenAPIHost string
	WebHost     string
	GatewayHost string
	CredPath    string // credentials.json 路径
	Persist     bool   // false 时全部内存态（测试用）
	Timeout     time.Duration

	// PollInterval 设了就用它替代 device flow 轮询间隔（测试加速）。
	PollInterval time.Duration
	Log          *slog.Logger

	http    *http.Client
	procMID string

	modelsCache *modelsCache

	mu     sync.Mutex
	cached *Credentials
}

// NewDefaultClient CN 区域默认装配（凭证路径在 stateDir 下）。
func NewDefaultClient(stateDir string, log *slog.Logger) *Client {
	return &Client{
		OpenAPIHost: proto.CNOpenAPIHost,
		WebHost:     proto.CNWebHost,
		GatewayHost: proto.GatewayHost,
		CredPath:    filepath.Join(stateDir, "credentials.json"),
		Persist:     true,
		Log:         log,
	}
}

func (c *Client) logf(format string, a ...any) {
	if c.Log != nil {
		c.Log.Info("[qoder_cosy] " + fmt.Sprintf(format, a...))
	}
}

// ProcessMachineID 进程级 machine_id：引导、签名头、续期都用它
// （Python _PROCESS_MACHINE_ID，落盘后随凭证复用 cred.machine_id）。
func (c *Client) ProcessMachineID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.procMID == "" {
		c.procMID = NewUUID()
	}
	return c.procMID
}

// ── 凭证文件 ─────────────────────────────────────────────────────────────────

func (c *Client) saveCred(cred *Credentials) {
	if !c.Persist || cred == nil {
		return
	}
	if cred.AccessToken == "" && cred.SecurityOauthToken == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(c.CredPath), 0o700); err != nil {
		c.logf("凭证落盘失败: %v", err)
		return
	}
	data, err := json.MarshalIndent(cred, "", "  ")
	if err != nil {
		c.logf("凭证序列化失败: %v", err)
		return
	}
	tmp := c.CredPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		c.logf("凭证落盘失败: %v", err)
		return
	}
	if err := os.Rename(tmp, c.CredPath); err != nil {
		c.logf("凭证落盘失败: %v", err)
	}
}

// SaveCred 供 handler 层登录成功后落盘（内部沿用 persist 开关）。
func (c *Client) SaveCred(cred *Credentials) { c.saveCred(cred) }

func (c *Client) loadCredFile() *Credentials {
	// 读文件不受 Persist 开关限制：PERSIST=0 只关「落盘写回」，
	// 已存在的 credentials.json 照常读取（Python 同语义）。
	data, err := os.ReadFile(c.CredPath)
	if err != nil {
		return nil
	}
	var cred Credentials
	if json.Unmarshal(data, &cred) != nil {
		return nil
	}
	if cred.AccessToken == "" && cred.SecurityOauthToken == "" {
		return nil
	}
	return &cred
}

// ── openapi 请求（带 2 次重试） ───────────────────────────────────────────────

// errText 非 2xx 的拒因：CLI 侧按 errorMessage/error_message/message/error 取值。
func errText(data map[string]any) string {
	for _, key := range []string{"errorMessage", "error_message", "message", "error", "errorCode", "code"} {
		if s, ok := data[key].(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)[:min(200, len(strings.TrimSpace(s)))]
		}
	}
	return ""
}

// OpenAPIRequest openapi.qoder.com.cn 的 JSON 请求，返回 (status, body dict)。
// 网络异常重试一次（睡 OPENAPI_RETRY_S）；全部失败返回 (0, {})。
func (c *Client) OpenAPIRequest(method, path string, jsonBody map[string]any, query string, bearer string) (int, map[string]any) {
	headers := map[string]string{"Accept": "application/json", "User-Agent": "Qoder"}
	if bearer != "" {
		headers["Authorization"] = "Bearer " + bearer
	}
	last := ""
	for attempt := 0; attempt < 2; attempt++ {
		status, data, err := c.openapiOnce(method, path, jsonBody, query, headers)
		if err == nil {
			if status < 200 || status >= 300 {
				c.logf("%s → HTTP %d %s", path, status, firstNonEmpty(errText(data), truncStr(mustJSON(data), 200)))
			}
			return status, data
		}
		last = err.Error()
		if attempt == 0 {
			time.Sleep(openapiRetryS * time.Second)
		}
	}
	c.logf("%s 请求异常: %s", path, last)
	return 0, map[string]any{}
}

func (c *Client) openapiOnce(method, path string, jsonBody map[string]any, query string, headers map[string]string) (int, map[string]any, error) {
	full := c.OpenAPIHost + path
	if query != "" {
		full += "?" + query
	}
	var bodyReader *strings.Reader
	if jsonBody != nil {
		data, err := marshalCompact(jsonBody)
		if err != nil {
			return 0, nil, err
		}
		bodyReader = strings.NewReader(string(data))
		headers["Content-Type"] = "application/json"
	} else {
		bodyReader = strings.NewReader("")
	}
	ctx, cancel := contextWithTimeout(openapiTimeoutS * time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, full, bodyReader)
	if err != nil {
		return 0, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.httpc().Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, _ := ioReadAll(ioLimit(resp.Body, 8<<20))
	var data map[string]any
	if json.Unmarshal(raw, &data) != nil || data == nil {
		data = map[string]any{}
	}
	return resp.StatusCode, data, nil
}

// httpc 惰性 http.Client。ResponseHeaderTimeout 对齐 requests 的 timeout 语义
// （连接+拿到响应头的超时，SSE 长流不被掐断）；openapi 请求另有 15s ctx 截止。
func (c *Client) httpc() *http.Client {
	if c.http == nil {
		c.http = &http.Client{Transport: &http.Transport{
			ResponseHeaderTimeout: c.Timeout,
			MaxIdleConnsPerHost:   8,
		}}
	}
	return c.http
}

// ── 过期换算（expires_at 秒/毫秒/ISO → epoch 秒） ─────────────────────────────

// expiresAt 支持 epoch 秒/毫秒/ISO；缺则用 expires_in 换算；都缺返回 0（未知）。
//
// inMs：expires_in 的单位是**毫秒**。jobToken 族全是毫秒（86400000 = 1 天），
// deviceToken 族是秒——必须由调用方按响应类型指定，不能靠数值大小猜。
func expiresAt(data map[string]any, prefix string, inMs bool) int64 {
	for _, key := range []string{prefix + "expires_at", prefix + "expiresAt", prefix + "expire_time"} {
		if v := numOrZero(data[key]); v > 0 {
			if v > 1e11 {
				return int64(v / 1000)
			}
			return int64(v)
		}
		if s, ok := data[key].(string); ok && s != "" {
			if t, err := time.Parse(time.RFC3339, strings.Replace(s, "Z", "+00:00", 1)); err == nil {
				return t.Unix()
			}
		}
	}
	for _, key := range []string{prefix + "expires_in", prefix + "expiresIn"} {
		if v := numOrZero(data[key]); v > 0 {
			if inMs {
				return NowUnix() + int64(v/1000)
			}
			return NowUnix() + int64(v)
		}
	}
	return 0
}

func numOrZero(v any) float64 {
	if f, ok := v.(float64); ok {
		return f
	}
	return 0
}

// CredApplied 把兑换/续期响应并进凭证；无 token 视为失败（返回 nil）。
func CredApplied(data map[string]any, base *Credentials, tokenType string) *Credentials {
	job := tokenType == "job"
	tok := ""
	for _, key := range []string{"token", "device_token", "access_token"} {
		if s, _ := data[key].(string); s != "" {
			tok = s
			break
		}
	}
	if tok == "" {
		return nil
	}
	cred := *base
	cred.SecurityOauthToken = tok
	cred.AccessToken = tok
	cred.TokenType = tokenType
	if exp := expiresAt(data, "", job); exp > 0 {
		cred.ExpireTime = exp
	}
	if refExp := expiresAt(data, "refresh_token_", job); refExp > 0 {
		if job {
			cred.JobRefreshTokenExpireTime = refExp
		} else {
			cred.RefreshTokenExpireTime = refExp
		}
	}
	if s, _ := data["refresh_token"].(string); s != "" {
		if job {
			// 别动凭长效登录态的 refresh_token
			cred.JobRefreshToken = s
		} else {
			cred.RefreshToken = s
		}
	}
	for _, key := range []string{"uid", "name", "email"} {
		if s, _ := data[key].(string); s != "" {
			switch key {
			case "uid":
				cred.UID = s
			case "name":
				cred.Name = s
			case "email":
				cred.Email = s
			}
		}
	}
	return &cred
}

// ── device flow ──────────────────────────────────────────────────────────────

// Authorization PKCE：verifier 本地留存，S256(challenge) 给页面。
// 返回 (authURL, verifier, nonce)。
func Authorization(webHost, deviceClientID, machineID string) (string, string, string) {
	raw := make([]byte, 64)
	rand.Read(raw)
	verifier := base64RawURL(raw)
	challenge := sha256B64url(verifier)
	nonce := NewUUID()
	q := urlValues(map[string]string{
		"challenge":        challenge,
		"challenge_method": "S256",
		"nonce":            nonce,
		"machine_id":       machineID,
		"client_id":        deviceClientID,
	})
	return webHost + proto.DeviceSelectAccountsPath + "?" + q, verifier, nonce
}

// PollDeviceToken 200 且 token 非空即成功；否则每 2s 再试，至超时。
// 404 属正常（未授权时 poll 就返回 404）。
func (c *Client) PollDeviceToken(nonce, verifier string) map[string]any {
	q := urlValues(map[string]string{
		"nonce":            nonce,
		"verifier":         verifier,
		"challenge_method": "S256",
	})
	endpoint := proto.DeviceTokenPollPath + "?" + q
	deadline := time.Now().Add(signInTimeoutS * time.Second)
	for time.Now().Before(deadline) {
		status, data := c.OpenAPIRequest(http.MethodGet, endpoint, nil, "", "")
		if status == 200 {
			if tok, _ := data["token"].(string); strings.TrimSpace(tok) != "" {
				return data
			}
		}
		if status != 404 {
			c.logf("[login] poll → HTTP %d", status)
		}
		wait := time.Duration(signInPollS) * time.Second
		if c.PollInterval > 0 {
			wait = c.PollInterval
		}
		time.Sleep(wait)
	}
	return nil
}

// DeviceFlowSignIn 阻塞 device flow：浏览器授权 → dt- 设备令牌 → 换 jt- job 令牌。
// 换不到 job token 也无妨——device token 同样能签名，只是少了那层短期凭据。
func (c *Client) DeviceFlowSignIn() (*Credentials, error) {
	machineID := c.ProcessMachineID()
	authURL, verifier, nonce := Authorization(c.WebHost, proto.CNDeviceClientID, machineID)
	c.logf("无本地凭证（credentials.json 缺失或不可用），需登录。请在浏览器授权（%ds 内）:\n  %s", signInTimeoutS, authURL)

	dt := c.PollDeviceToken(nonce, verifier)
	if dt == nil {
		c.logf("device flow 超时或被拒")
		return nil, errors.New("授权超时或被拒绝")
	}

	uid := ""
	if v, _ := dt["user_id"].(string); v != "" {
		uid = v
	} else if f, ok := dt["user_id"].(float64); ok {
		uid = fmt.Sprint(int64(f))
	}
	cred := CredApplied(dt, &Credentials{Source: "device", MachineID: machineID, UID: uid}, "device")
	if cred == nil {
		return nil, errors.New("device token 响应无 token")
	}
	status, ui := c.OpenAPIRequest(http.MethodGet, proto.UserinfoPath, nil, "", cred.AccessToken)
	if status == 200 {
		for _, key := range []string{"email", "name"} {
			if s, _ := ui[key].(string); s != "" {
				if key == "email" {
					cred.Email = s
				} else {
					cred.Name = s
				}
			}
		}
		if cred.UID == "" {
			for _, key := range []string{"id", "user_id", "uid"} {
				if s, _ := ui[key].(string); s != "" {
					cred.UID = s
					break
				}
				if f, ok := ui[key].(float64); ok {
					cred.UID = fmt.Sprint(int64(f))
					break
				}
			}
		}
	}

	// 换 job token。clientId 必须是 CNJobTokenClientID：拿 device flow 的
	// client_id 去换恒回 HTTP 400 BadRequest（2026-10-20 实测），换对了立刻 200。
	status, jr := c.OpenAPIRequest(http.MethodPost, proto.MeJobTokenPath,
		map[string]any{"clientId": proto.CNJobTokenClientID}, "", cred.AccessToken)
	if status == 200 {
		if job := CredApplied(jr, cred, "job"); job != nil {
			return job, nil
		}
	}
	c.logf("job token 未换到（HTTP %d），按 device token 签名", status)
	return cred, nil
}

// ── 续期 ─────────────────────────────────────────────────────────────────────

// RefreshCredential 续期。两套凭据各有各的刷新口，**不能互相顶替**：
//
//	deviceToken/refresh ← drt-（rotation，长效 30 天/1 年）
//	jobToken/refresh    ← jrt-（rotation，只活 2 天）
//
// 先按当前 token_type 走自己的口，都失败再退回长效的 device 续期 + 重新换一次 job token。
func (c *Client) RefreshCredential(cred *Credentials) *Credentials {
	type attempt struct {
		path string
		tt   string
		rt   string
	}
	var tries []attempt
	if cred.TokenType == "job" && cred.JobRefreshToken != "" {
		tries = append(tries, attempt{proto.JobRefreshPath, "job", cred.JobRefreshToken})
	}
	if cred.RefreshToken != "" {
		tries = append(tries, attempt{proto.DeviceRefreshPath, "device", cred.RefreshToken})
	}
	for _, tr := range tries {
		status, data := c.OpenAPIRequest(http.MethodPost, tr.path, map[string]any{"refresh_token": tr.rt}, "", "")
		if status != 200 {
			c.logf("续期 %s → HTTP %d", tr.path, status)
			continue
		}
		newCred := CredApplied(data, cred, tr.tt)
		if newCred == nil {
			c.logf("续期 %s 响应无 token", tr.path)
			continue
		}
		c.logf("凭证已续期（%s）", tr.path)
		if tr.tt == "device" && newCred.TokenType != "job" {
			// device token 刷成功了，但签名用的是 job——顺手再换一个，换不到就用 dt-。
			newCred = c.RenewJobFromDevice(newCred)
		}
		c.saveCred(newCred)
		return newCred
	}
	return nil
}

// RenewJobFromDevice 拿刚续好的 device token 换一个新 job token；失败原样返回（dt- 也能签名）。
func (c *Client) RenewJobFromDevice(cred *Credentials) *Credentials {
	dt := cred.AccessToken
	if !strings.HasPrefix(dt, "dt-") {
		return cred
	}
	status, jr := c.OpenAPIRequest(http.MethodPost, proto.MeJobTokenPath,
		map[string]any{"clientId": proto.CNJobTokenClientID}, "", dt)
	if status == 200 {
		if job := CredApplied(jr, cred, "job"); job != nil {
			c.logf("已用 device token 重新换到 job token")
			return job
		}
	}
	return cred
}

func expiring(cred *Credentials) bool {
	return cred.ExpireTime > 0 && cred.ExpireTime-NowUnix() < refreshLeadS
}

// LoadIdentity 取自有凭证：内存态（临近到期先续期）→ credentials.json → device flow 登录。
// forceRefresh 用于上游 401/403：跳过缓存，续期失败即重新登录。
func (c *Client) LoadIdentity(forceRefresh bool) (*Credentials, error) {
	c.mu.Lock()
	cached := c.cached
	c.mu.Unlock()
	if cached != nil && !forceRefresh && !expiring(cached) {
		return cached, nil
	}

	var cred *Credentials
	if cached != nil && (forceRefresh || expiring(cached)) {
		cred = c.RefreshCredential(cached)
	}
	if cred == nil {
		cred = c.loadCredFile()
		if cred != nil && expiring(cred) {
			if refreshed := c.RefreshCredential(cred); refreshed != nil {
				cred = refreshed
			}
		}
		if cred != nil {
			c.logf("已从 credentials.json 恢复凭证")
		}
	}
	if cred == nil {
		var err error
		cred, err = c.DeviceFlowSignIn()
		if err != nil {
			return nil, errors.New("no usable Qoder credential (credentials.json missing/unusable and device flow failed): " + err.Error())
		}
	}
	cred.MachineID = firstNonEmpty(cred.MachineID, c.ProcessMachineID())

	c.mu.Lock()
	c.cached = cred
	c.mu.Unlock()
	return cred, nil
}

// PeekCredential 当前凭据快照（内存缓存 > credentials.json），只读展示用：
// 绝不触发 device flow 登录或续期——面板打开不应产生登录副作用。无凭据返回 nil。
func (c *Client) PeekCredential() *Credentials {
	c.mu.Lock()
	cached := c.cached
	c.mu.Unlock()
	if cached != nil {
		return cached
	}
	return c.loadCredFile()
}

// MachineID 当前身份的 machine_id（LoadIdentity 时缓存）。
func (c *Client) MachineID(cred *Credentials) string {
	return firstNonEmpty(cred.MachineID, c.ProcessMachineID())
}

// Invalidate 丢弃进程内凭证缓存（仅本进程，无任何文件写入）。
func (c *Client) Invalidate() {
	c.mu.Lock()
	c.cached = nil
	c.mu.Unlock()
}

// Reauthenticate 上游 401/403 后强制重解析：先续期，续期被拒则 device flow 重登录。
func (c *Client) Reauthenticate() bool {
	if _, err := c.LoadIdentity(true); err != nil {
		c.Invalidate()
		c.logf("凭证重取失败: %v", err)
		return false
	}
	return true
}

// ── 小工具 ───────────────────────────────────────────────────────────────────

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func truncStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func mustJSON(v any) string {
	data, err := marshalCompact(v)
	if err != nil {
		return ""
	}
	return string(data)
}
