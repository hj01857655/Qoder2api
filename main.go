// Qoder2api Go 版入口。子命令：
//
//	qoder2api-go serve   启动 HTTP 服务（默认）
//	qoder2api-go login   阻塞式 device flow 登录（凭证落盘 credentials.json）
//	qoder2api-go claim   手动执行一次签到检查
package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"qoder2api/internal/config"
	"qoder2api/internal/dump"
	"qoder2api/internal/handler"
	"qoder2api/internal/qoder"
)

func main() {
	cfg := config.Load()
	log := handler.NewLogger(cfg.StateDir)

	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	q := qoder.NewDefaultClient(cfg.StateDir, log)
	q.Timeout = time.Duration(cfg.Timeout) * time.Second
	q.Persist = cfg.PersistCred
	// 端点覆盖：冒烟/联调时把上游指到本地假上游，全程离线
	if v := os.Getenv("QODER_OPENAPI_HOST"); v != "" {
		q.OpenAPIHost = v
	}
	if v := os.Getenv("QODER_GATEWAY_HOST"); v != "" {
		q.GatewayHost = v
	}
	if v := os.Getenv("QODER_WEB_HOST"); v != "" {
		q.WebHost = v
	}

	switch cmd {
	case "login":
		cred, err := q.DeviceFlowSignIn()
		if err != nil {
			fmt.Fprintln(os.Stderr, "登录失败:", err)
			os.Exit(1)
		}
		q.SaveCred(cred)
		fmt.Println("登录成功:", cred.Email)
	case "claim":
		b := benefit(q, cfg, log)
		result := b.CheckAndClaim()
		fmt.Println("reason:", result["reason"], "claimed:", result["claimed"])
	case "serve":
		serve(cfg, q, log)
	default:
		fmt.Fprintln(os.Stderr, "未知子命令:", cmd, "（可用: serve / login / claim）")
		os.Exit(2)
	}
}

func serve(cfg *config.Config, q *qoder.Client, log *slog.Logger) {
	_ = os.MkdirAll(cfg.StateDir, 0o700)
	s := &handler.Server{
		Cfg:  cfg,
		Q:    q,
		Dump: dump.New(cfg.DumpOn, cfg.DumpDir, cfg.DumpMaxFiles),
		Log:  log,
	}

	fmt.Printf("Qoder2api (Go) listening on %s:%d\n", config.ListenHost, cfg.Port)
	fmt.Printf("  state dir : %s\n", cfg.StateDir)
	fmt.Printf("  api key   : %s\n", map[bool]string{true: "enabled", false: "disabled"}[cfg.APIKey != ""])
	fmt.Printf("  persist   : %v\n", cfg.PersistCred)

	// 签到后台线程：无凭证时它会在 goroutine 里走 device flow（打印授权 URL），
	// 不阻塞 HTTP 服务本身。
	go benefit(q, cfg, log).StartDailyLoop()

	addr := fmt.Sprintf("%s:%d", config.ListenHost, cfg.Port)
	if err := http.ListenAndServe(addr, s.Handler()); err != nil {
		fmt.Fprintln(os.Stderr, "server exit:", err)
		os.Exit(1)
	}
}

func benefit(q *qoder.Client, cfg *config.Config, log *slog.Logger) *qoder.Benefit {
	return &qoder.Benefit{
		C:        q,
		MarkPath: filepath.Join(cfg.StateDir, ".coffee_claimed"),
		Log: func(msg string) {
			log.Info(msg)
		},
	}
}
