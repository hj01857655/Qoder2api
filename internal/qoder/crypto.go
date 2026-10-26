// Package qoder 对应 Python 版 lanes/qoder_cosy.py + oauth.py：COSY 直接 API 协议层。
// 本文件是编解码与签名原语（qoder_encode / sign_request / build_cosy_headers）。
//
// 约束：qoderEncode 的「首尾 1/3 交换」发生在标准 base64 字符串上，再整体映射
// 自定义字母表——交换与映射的顺序不能颠倒（proto.Alphabet 与 proto.StdB64 是
// 生成器从 Python 源逐字节提取的，解错顺序就是另一个密文空间）。
package qoder

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"runtime"
	"strings"

	"qoder2api/internal/proto"
)

// qoderAlphabetIdx 自定义字母表 → 标准字母表的映射表（Python _C2S，含 $ ↔ =）。
func buildMaps() (c2s map[rune]byte, s2c map[byte]rune) {
	c2s = make(map[rune]byte, 65)
	s2c = make(map[byte]rune, 65)
	std := []byte(proto.StdB64)
	for i, r := range proto.Alphabet {
		c2s[r] = std[i]
		s2c[std[i]] = r
	}
	// Python 额外把 '$' 当 '='：padding 字符被换成了 '$'
	c2s['$'] = '='
	s2c['='] = '$'
	return c2s, s2c
}

var c2s, s2c = buildMaps()

// QoderEncode UTF8 → 标准 base64 → 首尾 1/3 交换 → 映射自定义字母表。
func QoderEncode(plaintext []byte) string {
	std := base64.StdEncoding.EncodeToString(plaintext)
	n := len(std)
	t := n / 3
	swapped := std[n-t:] + std[t:n-t] + std[:t]
	var b strings.Builder
	b.Grow(n)
	for i := 0; i < n; i++ {
		if r, ok := s2c[swapped[i]]; ok {
			b.WriteRune(r)
		} else {
			b.WriteByte(swapped[i])
		}
	}
	return b.String()
}

// QoderDecode 自定义字母表 → 标准 base64 → 反交换 → 解码。
func QoderDecode(encoded string) ([]byte, error) {
	var buf strings.Builder
	buf.Grow(len(encoded))
	for _, r := range encoded {
		if b, ok := c2s[r]; ok {
			buf.WriteByte(b)
		} else {
			buf.WriteRune(r)
		}
	}
	mapped := buf.String()
	n := len(mapped)
	t := n / 3
	std := mapped[n-t:] + mapped[t:n-t] + mapped[:t]
	return base64.StdEncoding.DecodeString(std)
}

// SignRequest MD5(payload\n cosyKey\n date\n body\n path)（Python sign_request）。
func SignRequest(payloadB64, cosyKey, cosyDate, body, path string) string {
	sum := md5.Sum([]byte(payloadB64 + "\n" + cosyKey + "\n" + cosyDate + "\n" + body + "\n" + path))
	return hex.EncodeToString(sum[:])
}

// MachineOS 对齐 Python machine_os() / magpie MachineOS()：
// arch 映射（amd64→x86_64、arm64→aarch64），Windows 记作 win32。
func MachineOS() string {
	arch := runtime.GOARCH
	switch arch {
	case "amd64":
		arch = "x86_64"
	case "x86":
		arch = "x86"
	case "arm64":
		arch = "aarch64"
	}
	osName := runtime.GOOS
	if osName == "windows" {
		osName = "win32"
	}
	return arch + "_" + osName
}

// loadRSAPubkey 解析 proto.RSAPubkeyDERB64（SubjectPublicKeyInfo DER）。
func loadRSAPubkey() (*rsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(proto.RSAPubkeyDERB64)
	if err != nil {
		return nil, fmt.Errorf("解析 RSA 公钥 DER 失败: %w", err)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("解析 RSA 公钥失败: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("公钥类型不是 RSA")
	}
	return rsaPub, nil
}

// BuildCosyHeaders 构建 COSY 签名请求头（对齐 Python build_cosy_headers）：
//
//  1. user blob（uid/name/email/security_oauth_token）AES-128-CBC 加密，
//     key = IV = 随机 UUID 前 16 个 hex 的 ASCII
//  2. AES key 用 RSA PKCS1 v1.5 加密 → Cosy-Key
//  3. payload 对象（version/requestId/info/cosyVersion/ideVersion）标准 base64
//  4. 签名 path 去掉 /algo 前缀，MD5 五元组签名
//
// body 是已编码的 wire body（自定义 base64 后的字符串），签名原样取用。
func BuildCosyHeaders(rawURL, body string, ident *Credentials, machineID string, timestamp int64) (map[string]string, error) {
	if timestamp == 0 {
		timestamp = NowUnix()
	}

	// 1. user blob
	blobData := map[string]string{
		"uid":                  ident.UID,
		"aid":                  "",
		"name":                 ident.Name,
		"email":                ident.Email,
		"security_oauth_token": ident.SecurityOauthToken,
	}
	blobJSON, err := marshalCompact(blobData)
	if err != nil {
		return nil, err
	}
	aesKey := make([]byte, 16)
	if _, err := rand.Read(aesKey[:8]); err != nil {
		return nil, err
	}
	// key/IV = 16 个 hex 字符（8 字节随机数的 hex），ASCII 取用
	hexKey := hex.EncodeToString(aesKey[:8]) // 恰好 16 字符
	keyASCII := []byte(hexKey)

	block, err := aes.NewCipher(keyASCII)
	if err != nil {
		return nil, err
	}
	// PKCS7 pad（与 Python 手工 pad 一致：pad_len = 16 - len%16，恒补 1..16）
	padLen := 16 - len(blobJSON)%16
	padded := make([]byte, 0, len(blobJSON)+padLen)
	padded = append(padded, blobJSON...)
	for i := 0; i < padLen; i++ {
		padded = append(padded, byte(padLen))
	}
	iv := keyASCII // key = IV
	infoB64 := base64.StdEncoding.EncodeToString(cbcEncrypt(block, iv, padded))

	// 2. RSA 加密 AES key
	pub, err := loadRSAPubkey()
	if err != nil {
		return nil, err
	}
	keyB64Bytes, err := rsa.EncryptPKCS1v15(rand.Reader, pub, keyASCII)
	if err != nil {
		return nil, err
	}
	keyB64 := base64.StdEncoding.EncodeToString(keyB64Bytes)

	// 3. payload
	payloadObj := map[string]string{
		"version":     "v1",
		"requestId":   NewUUID(),
		"info":        infoB64,
		"cosyVersion": proto.CosyVersion,
		"ideVersion":  "",
	}
	payloadJSON, err := marshalCompact(payloadObj)
	if err != nil {
		return nil, err
	}
	payloadB64 := base64.StdEncoding.EncodeToString(payloadJSON)

	// 4. 签名 path：去掉 /algo 前缀
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("解析签名 URL 失败: %w", err)
	}
	path := u.Path
	path = strings.TrimPrefix(path, "/algo")

	// 5. 签名
	cosyDate := fmt.Sprint(timestamp)
	sig := SignRequest(payloadB64, keyB64, cosyDate, body, path)

	// 6. 完整头集（对齐 magpie）
	return map[string]string{
		"Accept":                "text/event-stream",
		"Accept-Encoding":       "identity",
		"Content-Type":          "application/json",
		"Authorization":         fmt.Sprintf("Bearer COSY.%s.%s", payloadB64, sig),
		"Cosy-Business-Product": "app",
		"Cosy-Business-Type":    "agent",
		"Cosy-ClientIp":         machineID,
		"Cosy-ClientType":       "10",
		"Cosy-Data-Policy":      "disagree",
		"Cosy-Date":             cosyDate,
		"Cosy-Key":              keyB64,
		"Cosy-MachineId":        machineID,
		"Cosy-MachineToken":     machineID,
		"Cosy-MachineType":      "5",
		"Cosy-MachineOS":        MachineOS(),
		"Cosy-Scene":            "app",
		"Cosy-User":             ident.UID,
		"Cosy-Version":          proto.CosyVersion,
		"Login-Version":         "v2",
	}, nil
}

func cbcEncrypt(block cipher.Block, iv, src []byte) []byte {
	out := make([]byte, len(src))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, src)
	return out
}

// marshalCompact JSON 紧凑序列化不转义 HTML（对齐 Python json.dumps separators, ensure_ascii=False）。
func marshalCompact(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// sha256B64url PKCE S256 challenge（oauth.py authorization）。
func sha256B64url(s string) string {
	sum := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
