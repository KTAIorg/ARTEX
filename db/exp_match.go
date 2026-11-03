package db

// EXP 指纹匹配语义（纯 Go，可脱离数据库测试）。
//
// 授权渗透测试平台的能力沉淀库配套匹配器：输入资产指纹 JSON，对 EXP 的
// fingerprint_match 条件做结构化匹配。只做匹配判定，不做授权判定——EXP
// 只在授权范围内使用，边界由任务 scope 与拦截层把关。
//
// EXP 指纹条件（exp_assets.fingerprint_match）：
//   {
//     "components": [ {"name":"RocketMQ", "version_range":">=4.0.0,<5.1.0"} ],
//     "ports":      [10911, 9876],
//     "paths":      ["/assets/", "/login"]
//   }
//   - components 条目之间 OR（任一组件命中即该维度通过）；未声明 = 不限组件。
//   - 条目内 name 与版本区间是 AND：name 命中且版本落在区间内才算该条目命中。
//   - name 忽略大小写、双向子串匹配（条件 "tomcat" 命中 "Apache Tomcat"，
//     条件 "Apache RocketMQ" 也命中解析出的 "RocketMQ"）。
//   - version_range 语法：逗号分隔的 `op version` 约束，op ∈ >= <= > < = !=
//     （= 可省略，如 "1.2.3"；"*" 或空 = 不限版本）。版本号容忍 v 前缀与
//     1~3+ 段数字（"2", "2.3", "2.3.1"），缺段按 0 补齐逐段数值比较。
//   - 声明了 version_range 而资产指纹只认出组件、认不出版本 → 判
//     version_mismatch（先验公式 P(指纹正确) 不允许含糊，宁缺勿假）。
//   - ports：声明即要求资产端口命中其中之一；资产端口未知（0）判不命中。
//   - paths：声明即要求资产路径包含其中任一特征（忽略大小写子串）；
//     资产路径未知（空）判不命中。
//   - dimensions 之间 AND：components ∧ ports ∧ paths（未声明的维度恒通过）。
//
// 资产指纹输入（服务层入口用）：
//   {
//     "technologies": ["Nginx/1.18.0", "Apache Tomcat 9.0.30"],   // 探测到的技术栈
//     "components":   [ {"name":"tomcat", "version":"9.0.30"} ],  // 显式组件(优先)
//     "port": 8080,
//     "path": "/manager/html",
//     "url":  "http://t:8080/manager/html"                        // 有 url 时补 path
//   }
//   technologies 的解析启发式：从第一个后跟数字(或 v+数字)的分隔符
//   (':' '/' ' ' '-')处切成 name/version，如 "Nginx/1.18.0" →
//   ("Nginx","1.18.0")；切不出版本则整串当组件名。
//
// 未命中原因直接用 exp_attempts.failure_reason 的口径：
//   fingerprint_mismatch（组件/端口/路径对不上）| version_mismatch（版本不符或未知）。

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ExpComponentCond 是指纹条件里的一个组件维度：name + 可选版本区间。
type ExpComponentCond struct {
	Name         string `json:"name"`
	VersionRange string `json:"version_range,omitempty"`
}

// ExpFingerprint 是 exp_assets.fingerprint_match 的结构化形态。
type ExpFingerprint struct {
	Components []ExpComponentCond `json:"components,omitempty"`
	Ports      []int              `json:"ports,omitempty"`
	Paths      []string           `json:"paths,omitempty"`
}

// AssetComponent 是资产指纹里的一个显式组件（探测引擎常见输出）。
type AssetComponent struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// AssetFingerprint 是待匹配的资产指纹输入（agent 从探测结果整理）。
type AssetFingerprint struct {
	Technologies []string         `json:"technologies,omitempty"`
	Components   []AssetComponent `json:"components,omitempty"`
	Port         int              `json:"port,omitempty"`
	Path         string           `json:"path,omitempty"`
	URL          string           `json:"url,omitempty"`
}

// =====================================================================
// 版本比较
// =====================================================================

// parseVersion 把 "v1.18.0" / "1.18" / "2" 解析成数值段；非数字版本返回 false。
func parseVersion(s string) ([]int, bool) {
	s = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(strings.ToLower(s)), "v"))
	if s == "" {
		return nil, false
	}
	parts := strings.Split(s, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		// 逐字符校验而不是 Atoi：避免 "1beta" 这类混排被整段吞进数字。
		for _, r := range p {
			if r < '0' || r > '9' {
				return nil, false
			}
		}
		if p == "" {
			return nil, false
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}

// compareVersions 逐段数值比较，缺段补 0（1.18 == 1.18.0）。
func compareVersions(a, b []int) int {
	max := len(a)
	if len(b) > max {
		max = len(b)
	}
	for i := 0; i < max; i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

type versionConstraint struct {
	op  string // >= <= > < = !=
	ver []int
}

// parseVersionRange 解析 ">=4.0.0,<5.1.0" 这类约束列表；"*"/空 = 不限（0 约束）。
func parseVersionRange(r string) ([]versionConstraint, error) {
	r = strings.TrimSpace(r)
	if r == "" || r == "*" {
		return nil, nil
	}
	var out []versionConstraint
	for _, part := range strings.Split(r, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		op := ""
		for _, cand := range []string{">=", "<=", "==", ">", "<", "!=", "="} {
			if strings.HasPrefix(part, cand) {
				op = cand
				break
			}
		}
		verStr := part
		if op != "" {
			verStr = strings.TrimPrefix(part, op)
		} else {
			op = "="
		}
		if op == "==" {
			op = "="
		}
		ver, ok := parseVersion(verStr)
		if !ok {
			return nil, fmt.Errorf("invalid version %q in range %q", verStr, r)
		}
		out = append(out, versionConstraint{op: op, ver: ver})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty version range %q", r)
	}
	return out, nil
}

// versionSatisfies 检查版本是否满足全部约束。
func versionSatisfies(ver []int, cs []versionConstraint) bool {
	for _, c := range cs {
		cmp := compareVersions(ver, c.ver)
		switch c.op {
		case ">=":
			if cmp < 0 {
				return false
			}
		case "<=":
			if cmp > 0 {
				return false
			}
		case ">":
			if cmp <= 0 {
				return false
			}
		case "<":
			if cmp >= 0 {
				return false
			}
		case "=":
			if cmp != 0 {
				return false
			}
		case "!=":
			if cmp == 0 {
				return false
			}
		}
	}
	return true
}

// =====================================================================
// 组件匹配
// =====================================================================

// nameMatch 组件名匹配：忽略大小写 + 双向子串（条件与解析名互为包含即命中）。
func nameMatch(condName, assetName string) bool {
	c := strings.ToLower(strings.TrimSpace(condName))
	a := strings.ToLower(strings.TrimSpace(assetName))
	if c == "" || a == "" {
		return false
	}
	return strings.Contains(a, c) || strings.Contains(c, a)
}

// splitTechnology 从探测技术串里切出组件名与版本。启发式：找第一个后跟
// 数字（或 v+数字）的分隔符 ':' '/' ' ' '-'；找不到则整串是名字、无版本。
func splitTechnology(s string) (name, version string) {
	s = strings.TrimSpace(s)
	runes := []rune(s)
	for i, r := range runes {
		if r != ':' && r != '/' && r != ' ' && r != '-' {
			continue
		}
		if i+1 >= len(runes) {
			continue
		}
		rest := runes[i+1:]
		// 容忍 v 前缀（"redis/v7.2.4"）。
		if rest[0] == 'v' || rest[0] == 'V' {
			rest = rest[1:]
		}
		if len(rest) > 0 && rest[0] >= '0' && rest[0] <= '9' {
			return strings.TrimSpace(string(runes[:i])), strings.TrimSpace(string(rest))
		}
	}
	return s, ""
}

// assetComponents 把资产指纹的显式组件 + technologies 解析结果统一成
// (name, version) 列表；显式条目在前（更可信，命中判定先用它）。
func (af *AssetFingerprint) assetComponents() []AssetComponent {
	out := make([]AssetComponent, 0, len(af.Components)+len(af.Technologies))
	out = append(out, af.Components...)
	for _, t := range af.Technologies {
		n, v := splitTechnology(t)
		if n != "" {
			out = append(out, AssetComponent{Name: n, Version: v})
		}
	}
	return out
}

// matchComponentDim 匹配组件维度。返回 (通过, 未命中原因)。
// 原因口径：有名字命中但版本不符/未知 → version_mismatch；名字全不命中 →
// fingerprint_mismatch。
func matchComponentDim(conds []ExpComponentCond, comps []AssetComponent) (bool, string) {
	nameHit := false
	for _, cond := range conds {
		if strings.TrimSpace(cond.Name) == "" {
			continue
		}
		cs, err := parseVersionRange(cond.VersionRange)
		if err != nil {
			// 条件本身写坏：视为该条目不命中，交给上层把 EXP 视为不可信。
			continue
		}
		for _, comp := range comps {
			if !nameMatch(cond.Name, comp.Name) {
				continue
			}
			if len(cs) == 0 {
				return true, "" // 不限版本，名字命中即通过
			}
			ver, ok := parseVersion(comp.Version)
			if !ok {
				nameHit = true // 认出组件但认不出版本，继续找带版本的命中
				continue
			}
			if versionSatisfies(ver, cs) {
				return true, ""
			}
			nameHit = true // 版本明确不符，继续找其他组件条目
		}
	}
	if nameHit {
		return false, string(ExpFailVersionMismatch)
	}
	return false, string(ExpFailFingerprintMismatch)
}

// assetPath 取资产路径：显式 Path 优先，否则从 URL 提取。
func (af *AssetFingerprint) assetPath() string {
	if p := strings.TrimSpace(af.Path); p != "" {
		return p
	}
	if u, err := url.Parse(strings.TrimSpace(af.URL)); err == nil && u.Path != "" {
		return u.Path
	}
	return ""
}

// =====================================================================
// 匹配入口
// =====================================================================

// MatchExpFingerprint 判定资产指纹是否命中一条 EXP 的指纹条件。
// 返回 (命中, 未命中原因)；原因使用 exp_attempts.failure_reason 口径
// （fingerprint_mismatch | version_mismatch），可直接沉淀进失败台账。
func MatchExpFingerprint(fp *ExpFingerprint, asset *AssetFingerprint) (bool, string) {
	if fp == nil {
		return true, "" // 无条件 = 通配（EXP 自己声明适用一切，慎用）
	}
	if len(fp.Components) > 0 {
		if asset == nil {
			return false, string(ExpFailFingerprintMismatch)
		}
		if ok, reason := matchComponentDim(fp.Components, asset.assetComponents()); !ok {
			return false, reason
		}
	}
	if len(fp.Ports) > 0 {
		if asset == nil || asset.Port <= 0 {
			return false, string(ExpFailFingerprintMismatch)
		}
		hit := false
		for _, p := range fp.Ports {
			if p == asset.Port {
				hit = true
				break
			}
		}
		if !hit {
			return false, string(ExpFailFingerprintMismatch)
		}
	}
	if len(fp.Paths) > 0 {
		if asset == nil {
			return false, string(ExpFailFingerprintMismatch)
		}
		path := strings.ToLower(asset.assetPath())
		if path == "" {
			return false, string(ExpFailFingerprintMismatch)
		}
		hit := false
		for _, want := range fp.Paths {
			if w := strings.ToLower(strings.TrimSpace(want)); w != "" && strings.Contains(path, w) {
				hit = true
				break
			}
		}
		if !hit {
			return false, string(ExpFailFingerprintMismatch)
		}
	}
	return true, ""
}

// ParseExpFingerprint 反序列化 exp_assets.fingerprint_match；空 JSON 视为
// 通配（无条件）。结构非法时报错（service 层在建库时用它把坏条件挡在门外）。
func ParseExpFingerprint(raw json.RawMessage) (*ExpFingerprint, error) {
	if len(raw) == 0 || string(raw) == "null" || strings.TrimSpace(string(raw)) == "{}" {
		return &ExpFingerprint{}, nil
	}
	var fp ExpFingerprint
	if err := json.Unmarshal(raw, &fp); err != nil {
		return nil, fmt.Errorf("fingerprint_match 不是合法的指纹条件 JSON: %w", err)
	}
	for _, c := range fp.Components {
		if strings.TrimSpace(c.Name) == "" {
			return nil, fmt.Errorf("fingerprint_match.components 存在空 name 条目")
		}
		if _, err := parseVersionRange(c.VersionRange); err != nil {
			return nil, fmt.Errorf("组件 %q 的 version_range 非法: %w", c.Name, err)
		}
	}
	return &fp, nil
}

// ParseAssetFingerprint 反序列化资产指纹输入（exp_list_matching 工具参数）。
// 容忍 null/空对象（等于只有端口/路径维度的稀疏指纹）。
func ParseAssetFingerprint(raw json.RawMessage) (*AssetFingerprint, error) {
	af := &AssetFingerprint{}
	if len(raw) == 0 || string(raw) == "null" {
		return af, nil
	}
	if err := json.Unmarshal(raw, &af); err != nil {
		return nil, fmt.Errorf("fingerprint 不是合法的资产指纹 JSON: %w", err)
	}
	return af, nil
}
