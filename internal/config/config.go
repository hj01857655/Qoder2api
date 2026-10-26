// Package config 装配 Qoder2api 的运行配置：.env 加载 + 端口/鉴权/超时 + 状态目录。
//
// 状态目录规则与 Python 版对齐（Python: dirname(abspath(__file__))）：
// 凭证 credentials.json、请求日志、dumps/、benefit 标记全部落在状态目录。
// 部署时把 exe 放进原 Qoder2api 目录（或设 QODER2API_STATE_DIR 指向它），
// 即可无缝接管 Python 版的 credentials.json。
package config

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	// ListenHost 是默认绑定地址：仅本机回环，避免未鉴权时暴露到局域网；
	// 需要对外（如 Docker 容器内）用 HOST 环境变量覆盖为 0.0.0.0。
	ListenHost  = "127.0.0.1"
	DefaultPort = 8388
)

type Config struct {
	Host         string
	APIKey       string
	Port         int
	StateDir     string // credentials.json / request.log / dumps/ / .coffee_claimed 所在
	Timeout      int    // QODER_TIMEOUT：上游响应头超时秒
	PersistCred  bool   // QODER_PERSIST=0 时凭证全内存态
	DumpOn       bool
	DumpDir      string
	DumpMaxFiles int
}

// StateFilePath 返回状态目录下的文件路径。
func (c *Config) StateFilePath(name string) string { return filepath.Join(c.StateDir, name) }

// Load 读取配置。优先级：环境变量 > .env > 默认值。
// .env 从状态目录和工作目录两处尝试（与 python-dotenv 的 load_dotenv 语义近似）。
func Load() *Config {
	c := &Config{
		Host:         ListenHost,
		Port:         DefaultPort,
		Timeout:      120,
		PersistCred:  true,
		DumpOn:       true,
		DumpMaxFiles: 200,
	}

	// 状态目录：env 显式指定 > exe 所在目录
	c.StateDir = os.Getenv("QODER2API_STATE_DIR")
	if c.StateDir == "" {
		if exe, err := os.Executable(); err == nil {
			c.StateDir = filepath.Dir(exe)
		} else {
			wd, _ := os.Getwd()
			c.StateDir = wd
		}
	}

	// .env：状态目录优先，其次工作目录；两处都有的键先到先得
	for _, dir := range []string{c.StateDir, mustWd()} {
		loadDotEnv(filepath.Join(dir, ".env"))
	}

	c.APIKey = strings.TrimSpace(os.Getenv("API_KEY"))
	if h := strings.TrimSpace(os.Getenv("HOST")); h != "" {
		c.Host = h
	}
	if p, err := strconv.Atoi(strings.TrimSpace(os.Getenv("PORT"))); err == nil && p > 0 {
		c.Port = p
	}
	if v, err := strconv.Atoi(strings.TrimSpace(os.Getenv("QODER_TIMEOUT"))); err == nil && v > 0 {
		c.Timeout = v
	}
	if strings.TrimSpace(os.Getenv("QODER_PERSIST")) == "0" {
		c.PersistCred = false
	}
	if v := strings.TrimSpace(os.Getenv("DUMP")); v == "0" {
		c.DumpOn = false
	}
	if v := strings.TrimSpace(os.Getenv("DUMP_MAX_FILES")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.DumpMaxFiles = n
		}
	}
	c.DumpDir = strings.TrimSpace(os.Getenv("DUMP_DIR"))
	if c.DumpDir == "" {
		c.DumpDir = filepath.Join(c.StateDir, "dumps")
	}
	return c
}

func mustWd() string {
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return wd
}

// loadDotEnv 极简 .env 解析：KEY=VALUE 行，# 注释，不展开变量，不覆盖已有 env。
func loadDotEnv(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		if k != "" && os.Getenv(k) == "" {
			os.Setenv(k, v)
		}
	}
}
