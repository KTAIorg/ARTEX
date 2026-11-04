// Package sigauth 提供服务间 Ed25519 短时令牌（对齐 settlement 到账系统的
// 「私钥只在签名方」原则）：调用方持私钥自签 5 分钟 JWT，接收侧只存公钥。
// 无第三方依赖；算法固定 EdDSA（header/payload/signature 均 base64url 无填充）。
package sigauth

import (
	"crypto/ed25519"
	"encoding/json"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	TTL      = 5 * time.Minute
	typHeader = `{"alg":"EdDSA","typ":"JWT"}`
)

var b64 = base64.RawURLEncoding

// Signer 签名方：私钥永不出本机。
type Signer struct {
	Service string
	Key     ed25519.PrivateKey
}

func (s *Signer) Token() (string, error) {
	if s.Key == nil {
		return "", errors.New("sigauth: 私钥未配置")
	}
	now := time.Now()
	var jti [8]byte
	rand.Read(jti[:])
	payload := fmt.Sprintf(`{"service":%q,"exp":%d,"iat":%d,"jti":%q}`,
		s.Service, now.Add(TTL).Unix(), now.Unix(), b64.EncodeToString(jti[:]))
	signing := b64.EncodeToString([]byte(typHeader)) + "." + b64.EncodeToString([]byte(payload))
	sig := ed25519.Sign(s.Key, []byte(signing))
	return signing + "." + b64.EncodeToString(sig), nil
}

// Verifier 验签方：只持公钥（可公开）。keyring 按 service 名索引，支持单独吊销。
type Verifier struct {
	mu   sync.RWMutex
	keys map[string]ed25519.PublicKey
}

func NewVerifier(pubs map[string]ed25519.PublicKey) *Verifier {
	return &Verifier{keys: pubs}
}

// ParsePubs 解析 "svc1=<b64pub>,svc2=<b64pub>" 形式的 env 配置。
func ParsePubs(s string) (map[string]ed25519.PublicKey, error) {
	out := map[string]ed25519.PublicKey{}
	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		name, val, ok := strings.Cut(pair, "=")
		if !ok {
			return nil, fmt.Errorf("sigauth: 公钥配置格式错误: %q", pair)
		}
		raw, err := b64.DecodeString(strings.TrimSpace(val))
		if err != nil {
			return nil, fmt.Errorf("sigauth: 公钥 %s base64 解码失败: %w", name, err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("sigauth: 公钥 %s 长度非法", name)
		}
		out[strings.TrimSpace(name)] = ed25519.PublicKey(raw)
	}
	return out, nil
}

// Verify 校验 Bearer 令牌，返回签发方 service 名。
func (v *Verifier) Verify(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errors.New("sigauth: 令牌格式非法")
	}
	h, p, sigB64 := parts[0], parts[1], parts[2]
	sig, err := b64.DecodeString(sigB64)
	if err != nil {
		return "", errors.New("sigauth: 签名解码失败")
	}
	payloadRaw, err := b64.DecodeString(p)
	if err != nil {
		return "", errors.New("sigauth: payload 解码失败")
	}
	var claims struct {
		Service string `json:"service"`
		Exp     int64  `json:"exp"`
	}
	if err := json.Unmarshal(payloadRaw, &claims); err != nil || claims.Service == "" {
		return "", errors.New("sigauth: payload 非法")
	}
	if time.Now().Unix() >= claims.Exp {
		return "", errors.New("sigauth: 令牌已过期")
	}
	v.mu.RLock()
	pub, ok := v.keys[claims.Service]
	v.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("sigauth: 未知服务 %q", claims.Service)
	}
	if !ed25519.Verify(pub, []byte(h+"."+p), sig) {
		return "", errors.New("sigauth: 签名校验失败")
	}
	return claims.Service, nil
}

// ParsePriv 解析 "service:<b64seed>" 私钥 env 值（SIGAUTH_PRIVATE_KEY）。
func ParsePriv(s string) (*Signer, error) {
	name, val, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok {
		return nil, errors.New("sigauth: 私钥配置格式非法（service:<b64seed>）")
	}
	seed, err := b64.DecodeString(strings.TrimSpace(val))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("sigauth: 私钥解码失败")
	}
	return &Signer{Service: name, Key: ed25519.NewKeyFromSeed(seed)}, nil
}

// PubB64 公钥序列化为 env 配置片段用的 base64url。
func PubB64(pub ed25519.PublicKey) string { return b64.EncodeToString(pub) }
