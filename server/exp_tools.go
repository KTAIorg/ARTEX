package server

// EXP 资产库（复利引擎）只读查询工具：exp_list_matching。给猎杀 agent
// （worker）与对话 agent（auto）用：输入资产指纹 → 输出命中的参数化 EXP
// （含参数模板/前置条件/执行模板/成功判定与历史命中率），照 vuln_tools.go
// 的模式注入（platformTools → hostTools）、tools 表按 agent 绑定过滤
// （seed 默认绑 auto+worker）。
//
// 本期只读：EXP 的登记/编辑/执行沉淀走 service 层（server/exp_library.go）
// 与管理接口，执行器接线计划见 docs/EXP资产库设计.md。EXP 只在授权范围
// 内使用——工具输出里带纪律提示，授权边界由任务 scope 与拦截层把关。

import (
	"context"
	"encoding/json"
	"strings"

	actool "github.com/Autumn-27/norma/tool"
)

// expToolKeys 是 EXP 资产库工具的 key 集：seed 时默认绑 auto+worker
// （对话 agent 与猎杀 agent 都要能查命中 EXP）。
var expToolKeys = map[string]bool{
	"exp_list_matching": true,
}

// expMatchItem 是 exp_list_matching 输出的紧凑形态：挑 agent 拿下目标要
// 用的字段（怎么准备参数、怎么打、怎么确认拿下），统计面带命中率帮助选型。
type expMatchItem struct {
	ID            int64           `json:"id"`
	Name          string          `json:"name"`
	Description   string          `json:"description,omitempty"`
	CveIDs        []string        `json:"cve_ids,omitempty"`
	Tags          []string        `json:"tags,omitempty"`
	Preconditions json.RawMessage `json:"preconditions,omitempty"`
	ParamsSchema  json.RawMessage `json:"params_schema,omitempty"`
	ExecTemplate  json.RawMessage `json:"exec_template,omitempty"`
	SuccessOracle json.RawMessage `json:"success_oracle,omitempty"`
	Version       int             `json:"version"`
	Attempts      int             `json:"attempts"`
	HitRate       float64         `json:"hit_rate"`
}

// toolExpListMatching exp_list_matching：输入资产指纹，输出命中的 EXP 列表。
func (s *Server) toolExpListMatching() actool.CoreTool {
	desc := "查询 EXP 资产库（平台的能力沉淀库）：输入一个目标资产的指纹，返回指纹命中的参数化 EXP（利用配方），含参数模板 params_schema、前置条件 preconditions、执行模板 exec_template、成功判定 success_oracle 与该 EXP 的历史命中率(attempts/hit_rate，成功率低或 oracle_not_matched 扎堆的 EXP 谨慎使用)。\n" +
		"fingerprint 字段：technologies 探测到的技术栈(如 [\"Nginx/1.18.0\",\"Apache Tomcat 9.0.30\"])；components 显式组件 [{\"name\":\"tomcat\",\"version\":\"9.0.30\"}]；port 端口；path 探测路径；url(有 url 时自动取 path)。EXP 的组件条件按名字(忽略大小写)+版本区间匹配，端口/路径条件命中其一即通过。\n" +
		"⚠️ 授权渗透测试平台能力沉淀库：命中 EXP 只能在已授权的目标范围内使用；执行后无论成败都要通过 exp_attempts 台账沉淀（服务层 RecordAttempt）。"
	schema := objSchema(map[string]any{
		"fingerprint": map[string]any{"type": "object", "description": "资产指纹 JSON：{technologies:[], components:[{name,version}], port, path, url}，至少给一个维度", "properties": map[string]any{
			"technologies": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "探测到的技术栈串，如 Nginx/1.18.0、Apache Tomcat 9.0.30"},
			"components":   map[string]any{"type": "array", "items": map[string]any{"type": "object"}, "description": "显式组件 [{\"name\":\"tomcat\",\"version\":\"9.0.30\"}]"},
			"port":         map[string]any{"type": "integer", "description": "目标端口"},
			"path":         map[string]any{"type": "string", "description": "探测到的路径，如 /manager/html"},
			"url":          map[string]any{"type": "string", "description": "目标 URL（有它可自动取 path）"},
		}},
	}, "fingerprint")
	return roTool("exp_list_matching", desc, schema, func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		var a struct {
			Fingerprint json.RawMessage `json:"fingerprint"`
		}
		_ = json.Unmarshal(in, &a)
		if len(a.Fingerprint) == 0 || string(a.Fingerprint) == "null" {
			return actool.Errorf("fingerprint 不能为空（至少给 technologies/components/port/path/url 之一）"), nil
		}
		lib := s.expLibrary()
		if lib == nil {
			return actool.Errorf("数据库未初始化，EXP 资产库不可用"), nil
		}
		hits, err := lib.MatchByFingerprint(a.Fingerprint)
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		items := make([]expMatchItem, 0, len(hits))
		for _, h := range hits {
			items = append(items, expMatchItem{
				ID: h.Exp.ID, Name: h.Exp.Name, Description: strings.TrimSpace(h.Exp.Desc),
				CveIDs: h.Exp.CveIDs, Tags: h.Exp.Tags,
				Preconditions: h.Exp.Pre, ParamsSchema: h.Exp.Params,
				ExecTemplate: h.Exp.Exec, SuccessOracle: h.Exp.Oracle,
				Version: h.Exp.Version, Attempts: h.Attempts, HitRate: h.HitRate,
			})
		}
		return jsonResult(map[string]any{"total": len(items), "items": items})
	})
}

// seedExpWorkerBinding 把 EXP 工具补绑到 worker（一次性，flag 守卫）：老库的
// tool 行首次 seed 时可能只绑了 auto，猎杀 agent 需要能查命中 EXP。用户后来
// 手动解绑不会被覆盖（flag 已落）。
func (s *Server) seedExpWorkerBinding() {
	const flag = "exp_worker_binding_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	keys := make([]string, 0, len(expToolKeys))
	for k := range expToolKeys {
		keys = append(keys, k)
	}
	if err := s.m.pg.AddAgentToToolBinding("worker", keys); err != nil {
		return // 不落 flag，下次启动重试
	}
	_ = s.m.pg.SetSetting(flag, "true")
}
