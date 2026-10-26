// Package qoder 的模型清单与限免门禁，对应 Python lanes/qoder_cosy.py 的模型段：
// fetch_models（带 TTL 缓存）、price_factor/is_free 判定、ensure_free_model 三拒。
//
// 为什么不放行付费档：/v1/models 只列限免模型，客户端却可以硬编码一个付费模型
// 照样调通——那等于把「免费」做成了看用户自觉。付费档会按 price_factor 真扣额度
// （Kimi-K3 是 1.4 倍），而用户从列表上看不出来。三种情况一律拒绝，且故意把原因
// 写清楚（哪个档、多少倍率、该用哪个）。
package qoder

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"qoder2api/internal/proto"
)

const modelCacheTTL = 300 * time.Second // 5 分钟

// ModelEntry 上游清单里的一条（key/display_name/原始 config）。
type ModelEntry struct {
	Key            string
	Name           string
	Config         map[string]any
	IsReasoning    bool
	MaxInputTokens int
}

// modelsCache 模型缓存（引擎实例级）。
type modelsCache struct {
	list  []ModelEntry
	stamp time.Time
}

// FetchModels 从 /algo/api/v2/model/list?Encode=1 获取模型清单，带 COSY 签名。
// 拉不到时返回缓存（可能为空切片），不报错——调用方按空列表走 FALLBACK。
func (c *Client) FetchModels() []ModelEntry {
	c.mu.Lock()
	hit := c.modelsCache
	c.mu.Unlock()
	if hit != nil && time.Since(hit.stamp) < modelCacheTTL {
		return hit.list
	}

	cred, err := c.LoadIdentity(false)
	if err != nil {
		c.logf("模型列表身份不可用: %v", err)
		return cachedList(hit)
	}
	url := c.GatewayHost + proto.ModelsPath
	headers, err := BuildCosyHeaders(url, "", cred, c.MachineID(cred), 0)
	if err != nil {
		c.logf("模型列表签名失败: %v", err)
		return cachedList(hit)
	}
	headers["Accept"] = "application/json"

	var resp int
	var body []byte
	for attempt := 0; attempt < 2; attempt++ {
		resp, body, err = c.gatewayGet(url, headers)
		if err != nil {
			c.logf("模型列表请求异常: %v", err)
			return cachedList(hit)
		}
		if (resp == 401 || resp == 403) && attempt == 0 {
			// 10605 是业务排队限流（isQueued/waitTime），换凭证没用：不续期、
			// 不在这里重发（会放大请求量），直接返回旧缓存
			if strings.Contains(truncStr(string(body), 500), "10605") {
				break
			}
			c.Reauthenticate()
			if cred, err = c.LoadIdentity(true); err != nil {
				return cachedList(hit)
			}
			headers, _ = BuildCosyHeaders(url, "", cred, c.MachineID(cred), 0)
			headers["Accept"] = "application/json"
			continue
		}
		break
	}
	if resp != 200 {
		c.logf("模型列表获取失败: HTTP %d", resp)
		return cachedList(hit)
	}

	models := parseModelList(body)
	if len(models) > 0 {
		c.mu.Lock()
		c.modelsCache = &modelsCache{list: models, stamp: time.Now()}
		c.mu.Unlock()
		c.logf("获取到 %d 个模型", len(models))
	}
	return models
}

func cachedList(hit *modelsCache) []ModelEntry {
	if hit != nil {
		return hit.list
	}
	return nil
}

// parseModelList 解析 model/list 响应：data["chat"] 数组，enable=true 且
// key 不在 ("", "auto", "default")。
func parseModelList(body []byte) []ModelEntry {
	var data struct {
		Chat []map[string]any `json:"chat"`
	}
	if jsonUnmarshal(body, &data) != nil {
		return nil
	}
	models := []ModelEntry{}
	for _, raw := range data.Chat {
		if en, _ := raw["enable"].(bool); !en {
			continue
		}
		key, _ := raw["key"].(string)
		if key == "" || key == "auto" || key == "default" {
			continue
		}
		name := key
		if s, ok := raw["display_name"].(string); ok && s != "" {
			name = s
		}
		e := ModelEntry{
			Key:         key,
			Name:        name,
			Config:      raw,
			IsReasoning: boolOr(raw["is_reasoning"]),
		}
		if f := numOrZero(raw["max_input_tokens"]); f > 0 {
			e.MaxInputTokens = int(f)
		}
		models = append(models, e)
	}
	return models
}

// gatewayGet 带签名头打网关 GET（模型列表用；15s 超时）。
func (c *Client) gatewayGet(url string, headers map[string]string) (int, []byte, error) {
	ctx, cancel := contextWithTimeout(openapiTimeoutS * time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
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
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return resp.StatusCode, body, nil
}

// PriceFactor 取模型倍率（price_factor）；取不到返回 nil。
// 上游换类型不是没可能——字符串 "0.0" 按数字比是 False，会把免费模型误判成
// 收费，统一转 float。
func PriceFactor(m ModelEntry) *float64 {
	if m.Config == nil {
		return nil
	}
	switch v := m.Config["price_factor"].(type) {
	case float64:
		return &v
	case string:
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return &f
		}
	}
	return nil
}

// IsFreeModel 模型是否限免：price_factor 为 0 或 is_free 为 true。
func IsFreeModel(m ModelEntry) bool {
	if m.Config != nil && boolOr(m.Config["is_free"]) {
		return true
	}
	if pf := PriceFactor(m); pf != nil {
		return *pf == 0.0
	}
	return false
}

// EntryRecord 给 /v1/models 用的一条记录：标准字段外附带倍率信息。
type EntryRecord struct {
	Key                 string   `json:"key"`
	Name                string   `json:"name"`
	PriceFactor         *float64 `json:"price_factor"`
	IsFree              bool     `json:"is_free"`
	OriginalPriceFactor any      `json:"original_price_factor"`
	ContextWindow       int      `json:"context_window"`
	SupportsVision      bool     `json:"supports_vision"`
	IsReasoning         bool     `json:"is_reasoning"`
}

// ModelEntryOf ModelEntry → EntryRecord。
func ModelEntryOf(m ModelEntry) EntryRecord {
	r := EntryRecord{
		Key:            m.Key,
		Name:           m.Name,
		PriceFactor:    PriceFactor(m),
		IsFree:         IsFreeModel(m),
		IsReasoning:    m.IsReasoning,
		SupportsVision: boolOr(m.Config["is_vl"]),
	}
	if m.Config != nil {
		r.OriginalPriceFactor = m.Config["original_price_factor"]
	}
	if m.MaxInputTokens > 0 {
		r.ContextWindow = m.MaxInputTokens
	}
	return r
}

// ListModelEntries 限免模型的完整信息（含倍率）；取不到上游列表时回落 FALLBACK_MODELS。
//
// 兜底名单**故意只放限免的两个**：一旦包含收费模型，网络抖动时就会静默把付费档
// 推给客户端，错的方向最坏——宁可漏推荐，不可错推荐。它是「拉不到列表时不得不给
// 点什么」的最后手段，不是事实来源（真相永远在 model/list 的 price_factor 里）。
func (c *Client) ListModelEntries() []EntryRecord {
	models := c.FetchModels()
	free := []EntryRecord{}
	for _, m := range models {
		if IsFreeModel(m) {
			free = append(free, ModelEntryOf(m))
		}
	}
	if len(free) > 0 {
		return free
	}
	for _, n := range proto.FallbackModels {
		zero := 0.0
		free = append(free, EntryRecord{
			Key: n, Name: n, PriceFactor: &zero, IsFree: true,
		})
	}
	return free
}

// ListModelIDs 模型 ID 列表（用显示名，客户端友好）——只输出限免模型。
func (c *Client) ListModelIDs() []string {
	ids := []string{}
	for _, e := range c.ListModelEntries() {
		ids = append(ids, e.Name)
	}
	return ids
}

// ResolveModel 按 key / display_name / 模糊 找到模型条目。
func (c *Client) ResolveModel(modelKey string) *ModelEntry {
	models := c.FetchModels()
	lk := strings.ToLower(strings.TrimSpace(modelKey))
	if lk == "" {
		return nil
	}
	for i := range models { // 精确 key
		if models[i].Key == modelKey {
			return &models[i]
		}
	}
	for i := range models { // 精确显示名
		if models[i].Name == modelKey {
			return &models[i]
		}
	}
	for i := range models { // 模糊（兼容客户端的大小写/别名）
		if strings.Contains(strings.ToLower(models[i].Name), lk) ||
			strings.Contains(strings.ToLower(models[i].Key), lk) {
			return &models[i]
		}
	}
	return nil
}

// DefaultModelName 客户端没填 model 时用的档：取限免名单第一个（当前是 Qwen3.8-Flash）。
// 不能给空串——上游 X-Model-Key 必填；也不给 "auto"——上游没有这个模型。
func (c *Client) DefaultModelName() string {
	ids := c.ListModelIDs()
	if len(ids) > 0 {
		return ids[0]
	}
	if len(proto.FallbackModels) > 0 {
		return proto.FallbackModels[0]
	}
	return ""
}

// EnsureFreeModel 校验模型是否限免，**返回实际要用的模型名**（空值归一成默认档）。
// 三拒：明确收费（price_factor>0）、上游列表里根本没有、拉不到列表（只认 FALLBACK）。
func (c *Client) EnsureFreeModel(modelKey string) (string, error) {
	// 空 model 不算错：OpenAI 协议里它是可选字段。上游没有 "auto"，空串必挂，
	// 统一落到默认限免档。
	if strings.TrimSpace(modelKey) == "" {
		return c.DefaultModelName(), nil
	}

	models := c.FetchModels()
	if len(models) == 0 {
		for _, n := range proto.FallbackModels {
			if modelKey == n {
				return modelKey, nil
			}
		}
		return "", &ModelNotAllowedError{Message: "模型 '" + modelKey + "' 不可用（上游模型列表暂时取不到，仅允许 " +
			strings.Join(proto.FallbackModels, ", ") + "）"}
	}

	entry := c.ResolveModel(modelKey)
	if entry == nil {
		avail := freeNames(models)
		return "", &ModelNotAllowedError{Message: "未知模型 '" + modelKey + "'。当前可用（限免）：" + avail}
	}
	if !IsFreeModel(*entry) {
		pf := "None"
		if p := PriceFactor(*entry); p != nil {
			pf = strconv.FormatFloat(*p, 'g', -1, 64)
		}
		avail := freeNames(models)
		return "", &ModelNotAllowedError{Message: "模型 '" + entry.Name + "' 不在限免范围（price_factor=" + pf +
			"），已拒绝以免扣额度。请改用：" + avail}
	}
	return entry.Name, nil
}

func freeNames(models []ModelEntry) string {
	names := []string{}
	for _, m := range models {
		if IsFreeModel(m) {
			names = append(names, m.Name)
		}
	}
	if len(names) == 0 {
		return "无"
	}
	return strings.Join(names, ", ")
}

// FindModelConfig 查找模型的完整配置（用于请求体 model_config）：
// 先精确匹配 key，再精确匹配 display_name，再模糊匹配。
func (c *Client) FindModelConfig(modelKey string) map[string]any {
	models := c.FetchModels()
	for _, m := range models {
		if m.Key == modelKey {
			return m.Config
		}
	}
	for _, m := range models {
		if m.Name == modelKey {
			return m.Config
		}
	}
	lk := strings.ToLower(modelKey)
	for _, m := range models {
		if strings.Contains(strings.ToLower(m.Name), lk) || strings.Contains(strings.ToLower(m.Key), lk) {
			return m.Config
		}
	}
	return nil
}
