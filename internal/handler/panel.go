// 面板：/admin 静态页 + /admin/api/overview 概览。内置一份 panel.html（//go:embed），
// 状态目录里有同名文件时优先用用户的——内置版只是让 /admin 开箱即用，不依赖手动步骤。
package handler

import (
	_ "embed"
	"fmt"
	"net/http"
	"os"
	"time"
)

//go:embed panel.html
var panelBuiltin []byte

// servePanel 输出面板 HTML：状态目录 panel.html > 内置版。
func (s *Server) servePanel(w http.ResponseWriter, r *http.Request) {
	raw, err := os.ReadFile(s.Cfg.StateFilePath("panel.html"))
	if err != nil || len(raw) == 0 {
		raw = panelBuiltin
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(raw)
}

// adminOverview 面板概览。凭据走只读快照（不触发登录/续期——打开面板不应产生
// device flow 副作用）；模型列表与 /v1/models 同源（限免清单，含倍率信息）。
func (s *Server) adminOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.methodNotAllowed(w, r)
		return
	}
	cred := map[string]any{
		"valid": false, "email": "", "name": "", "uid": "",
		"token_type": "", "expire_text": "—", "notice": "",
	}
	if c := s.Q.PeekCredential(); c != nil {
		cred["valid"] = true
		cred["email"] = c.Email
		cred["name"] = c.Name
		cred["uid"] = c.UID
		cred["token_type"] = c.TokenType
		cred["expire_text"] = expireText(c.ExpireTime)
	} else {
		cred["notice"] = "无可用凭证（credentials.json 缺失或不可用），请点「重新登录」走 device flow"
	}
	models := make([]any, 0)
	for _, e := range s.Q.ListModelEntries() {
		models = append(models, e)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"service":    "Qoder2api",
		"credential": cred,
		"models":     models,
		"local_auth": s.Cfg.APIKey != "",
	})
}

// expireText 凭据到期时间的人类描述（0 = 未知）。
func expireText(expire int64) string {
	if expire <= 0 {
		return "未知"
	}
	d := time.Until(time.Unix(expire, 0))
	if d <= 0 {
		return "已过期（发请求时会自动尝试续期）"
	}
	if d < time.Hour {
		return fmt.Sprintf("%.0f 分钟后到期", d.Minutes())
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%.1f 小时后到期", d.Hours())
	}
	return fmt.Sprintf("%.1f 天后到期", d.Hours()/24)
}
