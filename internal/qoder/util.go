// Package qoder 的小工具：net/http 与 base64/url 的薄封装（集中在此便于注入测试）。
package qoder

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/url"
	"time"
)

func contextWithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

func ioReadAll(r io.Reader) ([]byte, error) { return io.ReadAll(r) }

func ioLimit(r io.Reader, n int64) io.Reader { return io.LimitReader(r, n) }

func urlValues(m map[string]string) string {
	v := url.Values{}
	for k, val := range m {
		v.Set(k, val)
	}
	return v.Encode()
}

// base64RawURL 无 padding 的 urlsafe base64（Python .rstrip("=") 语义）。
func base64RawURL(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func jsonUnmarshal(data []byte, v any) error { return json.Unmarshal(data, v) }

func boolOr(v any) bool {
	b, _ := v.(bool)
	return b
}

func intOr(v any) int {
	if f, ok := v.(float64); ok {
		return int(f)
	}
	return 0
}
