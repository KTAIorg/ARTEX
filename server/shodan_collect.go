package server

// Shodan 采集入口（kt-k8s#192 第 4/5 件）：CVE 列表「从 Shodan 采集」按钮的 HTTP
// 端点 + Agent 工具 shodan_collect。
//
// 采集器（shodan-collector）常驻主站 B 机，PG 队列消费、每页 1 credit。本模块只做
// 入队代理（POST {COLLECTOR_URL}/jobs，Bearer COLLECTOR_TOKEN），不做采集本身。
// 环境未配置时按钮/工具返回可读错误，不 panic。
//
// 队列语义（与 collector internal/queue 对齐）：
//   - 同 query 的 pending job 幂等合并，不重复扣 credit
//   - max_pages 每页 1 credit、100 条/页；断点续跑从 checkpoint 页继续

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Autumn-27/artex/server/sigauth"
	actool "github.com/Autumn-27/norma/tool"
)

const (
	envCollectorURL   = "COLLECTOR_URL"
	envCollectorToken = "COLLECTOR_TOKEN"

	collectorUserAgent = "artex-shodan-collect/1.0"
	collectorTimeout   = 15 * time.Second
)

func collectorConfigured() bool {
	return strings.TrimSpace(os.Getenv(envCollectorURL)) != ""
}

// collectorAuthHeader 取调用采集器的 Authorization 值：优先 Ed25519 短时令牌
// （SIGAUTH_PRIVATE_KEY，私钥只在本机），回落共享 COLLECTOR_TOKEN（迁移期）。
func collectorAuthHeader() (string, error) {
	if kv := strings.TrimSpace(os.Getenv("SIGAUTH_PRIVATE_KEY")); kv != "" {
		signer, err := sigauth.ParsePriv(kv)
		if err != nil {
			return "", fmt.Errorf("SIGAUTH_PRIVATE_KEY 解析失败: %w", err)
		}
		tok, err := signer.Token()
		if err != nil {
			return "", err
		}
		return "Bearer " + tok, nil
	}
	if tok := strings.TrimSpace(os.Getenv(envCollectorToken)); tok != "" {
		return "Bearer " + tok, nil
	}
	return "", nil
}

func collectorConfiguredError() error {
	return fmt.Errorf("管理员未配置 %s / %s（Shodan 采集器服务地址与令牌），采集功能暂不可用", envCollectorURL, envCollectorToken)
}

// collectorEnqueue 入队一个采集 job；返回 (jobID, error)。
func collectorEnqueue(ctx context.Context, query string, maxPages int, reason, createdBy string) (int64, error) {
	base := strings.TrimRight(strings.TrimSpace(os.Getenv(envCollectorURL)), "/")
	if base == "" {
		return 0, collectorConfiguredError()
	}
	if maxPages <= 0 {
		maxPages = 5
	}
	body, err := json.Marshal(map[string]any{
		"query": query, "max_pages": maxPages,
		"reason": reason, "created_by": createdBy,
	})
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/jobs", bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", collectorUserAgent)
	if auth, err := collectorAuthHeader(); err != nil {
		return 0, err
	} else if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	client := &http.Client{Timeout: collectorTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("采集器不可达: %w", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("采集器入队 HTTP %d: %s", resp.StatusCode, string(rb))
	}
	var out struct {
		JobID int64  `json:"job_id"`
		Query string `json:"query"`
	}
	if err := json.Unmarshal(rb, &out); err != nil || out.JobID == 0 {
		return 0, fmt.Errorf("采集器响应异常: %s", string(rb))
	}
	return out.JobID, nil
}

// collectorStats 队列概览（GET /status）。
func collectorStats(ctx context.Context) (map[string]int64, error) {
	base := strings.TrimRight(strings.TrimSpace(os.Getenv(envCollectorURL)), "/")
	if base == "" {
		return nil, collectorConfiguredError()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/status", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", collectorUserAgent)
	if auth, err := collectorAuthHeader(); err != nil {
		return nil, err
	} else if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := (&http.Client{Timeout: collectorTimeout}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("采集器不可达: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("采集器状态 HTTP %d", resp.StatusCode)
	}
	var out map[string]int64
	return out, json.NewDecoder(resp.Body).Decode(&out)
}

// ---- HTTP 端点（admin 门：采集花 credit，只允许管理员触发）----

func (s *Server) shodanCollect(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Query    string `json:"query"`
		MaxPages int    `json:"max_pages"`
		CveID    string `json:"cve_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	in.Query = strings.TrimSpace(in.Query)
	if in.Query == "" {
		writeErr(w, http.StatusBadRequest, "query 必填（Shodan 查询体，如 \"log4j country:CN\"）")
		return
	}
	reason := "artex:manual"
	if in.CveID != "" {
		reason = "artex:cve:" + in.CveID
	}
	ctx, cancel := context.WithTimeout(r.Context(), collectorTimeout)
	defer cancel()
	jobID, err := collectorEnqueue(ctx, in.Query, in.MaxPages, reason, "artex-web")
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"job_id": jobID, "query": in.Query,
		"message": fmt.Sprintf("已入队（job #%d），采集器将按队列执行并自动入库", jobID),
	})
}

func (s *Server) shodanCollectStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), collectorTimeout)
	defer cancel()
	stats, err := collectorStats(ctx)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// ---- Agent 工具 shodan_collect（与 vuln 工具同模式，绑 auto+worker）----

func (s *Server) toolShodanCollect() actool.CoreTool {
	desc := "把一个 Shodan 查询体加入采集队列（按 CVE 价值采集互联网资产并自动入库 kt-vuln）。\n" +
		"• query 是 Shodan 查询语法，如 \"log4j country:CN\"、\"nginx country:US\"；每个不同 query 首次 1 credit\n" +
		"• max_pages 每页 1 credit、100 条/页，默认 5；同 query 的 pending job 幂等合并，不会重复扣费\n" +
		"• 采集是异步的：本工具只入队，完成后资产出现在 vuln_search_assets / 资产列表（source=shodan）\n" +
		"• credit 是月度订阅额度（用不完会作废），对高价值 CVE 优先采集；status 可查队列概览"
	schema := objSchema(map[string]any{
		"query":     strParam("Shodan 查询体，如 \"log4j country:CN\"（支持 product/country/port 等 filter）"),
		"max_pages": map[string]any{"type": "integer", "description": "最多翻页数，每页 1 credit、100 条，默认 5"},
		"cve_id":    strParam("可选：关联的 CVE 编号，写进入队原因便于溯源"),
		"status":    map[string]any{"type": "boolean", "description": "true 时不入队，只返回队列概览"},
	}, "query")
	return roTool("shodan_collect", desc, schema, func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		var a struct {
			Query    string `json:"query"`
			MaxPages int    `json:"max_pages"`
			CveID    string `json:"cve_id"`
			Status   bool   `json:"status"`
		}
		_ = json.Unmarshal(in, &a)
		if a.Status {
			stats, err := collectorStats(ctx)
			if err != nil {
				return actool.Result{}, err
			}
			b, _ := json.MarshalIndent(stats, "", " ")
			return actool.Text("采集队列概览（按状态计数的 job 数）：\n" + string(b)), nil
		}
		a.Query = strings.TrimSpace(a.Query)
		if a.Query == "" {
			return actool.Result{}, fmt.Errorf("query 必填（Shodan 查询体，如 \"log4j country:CN\"）")
		}
		reason := "artex:agent"
		if a.CveID != "" {
			reason = "artex:cve:" + a.CveID
		}
		jobID, err := collectorEnqueue(ctx, a.Query, a.MaxPages, reason, "artex-agent")
		if err != nil {
			return actool.Result{}, err
		}
		return actool.Text(fmt.Sprintf("已入队采集（job #%d）：query=%q。采集是异步的，完成后资产自动入库（source=shodan），可用 vuln_search_assets 查询。", jobID, a.Query)), nil
	})
}

// faviconOverride 提供本站专属图标（FAVICON_B64，PNG base64）。
func (s *Server) faviconOverride(w http.ResponseWriter, r *http.Request) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(os.Getenv("FAVICON_B64")))
	if err != nil || len(raw) == 0 {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(raw)
}
