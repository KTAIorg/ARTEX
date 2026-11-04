package server

// SOP 角色化（docs/adr/角色化设计.md）的 agent seed：预置「武器匠」「收割机」两个
// 角色化 agent，猎杀/收割分流的最小接线。
//
// 模式与 seedReporterAgent 相同：一次性 flag 守卫（无论成败只试一次）、key 已被
// 用户占用时不覆盖、SeedPromptIfEmpty 播默认提示词（页面编辑不被覆盖）、
// AddAgentToToolBinding 绑各自工具白名单（用户手动解绑不被覆盖，因为本 seed 只在
// agent 首建时跑一次）。weapon_smith 串行（猎杀流，贵、低吞吐）；harvester
// parallel + none（收割流，一目标一收割、可高并发，merge 必须 none 否则一波目标
// 会被合并成一次运行、并行就没意义）。
//
// 只建 agent 不建触发器：触发链（insert_assets → 收割机指纹队列、收割成功 →
// 验证员、confirmed → 记录员）的接线计划见 docs/adr/角色化设计.md §7。侦察员/
// 验证员/记录员本期只交付 skill 文档，等触发器接线一起 seed。

import (
	"log"

	"github.com/Autumn-27/artex/agent"
)

// sopAgentSeed 描述一个 SOP 角色 agent 的最小预置内容。
type sopAgentSeed struct {
	key       string // agents.key（小写下划线，schema CHECK 约束）
	name      string // 展示名
	desc      string // agents.description
	prompt    string // 默认提示词（SeedPromptIfEmpty，仅空时写入）
	skill     string // 绑定的 SOP 角色 skill 目录名（agent_skill_visibility）
	tools     []string
	webSearch bool
	// runMode/mergeMode/maxParallel：空串 = 不设置（保持库默认 serial/all/5）。
	runMode     string
	mergeMode   string
	maxParallel int
}

// sopAgentSeeds 是本期预置的两个角色：武器匠（猎杀流）与收割机（收割流）。
var sopAgentSeeds = []sopAgentSeed{
	{
		key:    "weapon_smith",
		name:   "武器匠",
		desc:   "EXP 编写流水线（猎杀流，唯一需要强模型的角色）：CVE 富化 → 参考 PoC → 参数化 EXP → 靶场验证 → 提交入库。",
		prompt: agent.WeaponSmithDefaultPrompt,
		skill:  "weapon-smith",
		// 工具白名单见 skills/weapon-smith/SKILL.md：富化 + 验证 + 靶场指纹核对。
		tools: []string{"vuln_enrich_cve", "atomic_verify_poc", "atomic_fingerprint"},
		// 第 2 步找参考 PoC 需要 web 搜索（仍受全局开关 + 后端/key 配置约束）。
		webSearch: true,
	},
	{
		key:    "harvester",
		name:   "收割机",
		desc:   "EXP 库命中项的确定性批量执行（收割流：并行、便宜、无 LLM 判断）：指纹查命中 → 按参数模板执行 → 记录 attempt。",
		prompt: agent.HarvesterDefaultPrompt,
		skill:  "harvester",
		// 工具白名单见 skills/harvester/SKILL.md：查命中 + 三个原子操作。
		tools:       []string{"exp_list_matching", "atomic_weak_cred", "atomic_verify_poc", "atomic_fingerprint"},
		runMode:     "parallel",
		mergeMode:   "none",
		maxParallel: 8,
	},
}

// seedSopRoleAgents 预置武器匠/收割机两个 SOP 角色 agent（一次性，flag 守卫）。
func (s *Server) seedSopRoleAgents() {
	const flag = "sop_role_agents_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }() // 无论成功与否只尝试一次

	for _, seed := range sopAgentSeeds {
		if exist, _ := s.m.pg.GetAgentByKey(seed.key); exist != nil {
			continue // key 已被占用(用户手建过)——不覆盖
		}
		a, err := s.m.pg.CreateAgent(seed.key, seed.name, seed.desc)
		if err != nil {
			log.Printf("[sop-roles] 创建 %s 失败: %v", seed.key, err)
			continue
		}
		if err := s.m.pg.SeedPromptIfEmpty(a.ID, seed.prompt); err != nil {
			log.Printf("[sop-roles] %s seed prompt 失败: %v", seed.key, err)
		}
		if seed.webSearch {
			if err := s.m.pg.SetAgentWebSearch(seed.key, true); err != nil {
				log.Printf("[sop-roles] %s 开 web_search 失败: %v", seed.key, err)
			}
		}
		if seed.runMode != "" {
			if err := s.m.pg.SetAgentTriggerBehavior(seed.key, seed.runMode, seed.mergeMode, seed.maxParallel); err != nil {
				log.Printf("[sop-roles] %s 设置触发运行策略失败: %v", seed.key, err)
			}
		}
		if err := s.m.pg.AddAgentToToolBinding(seed.key, seed.tools); err != nil {
			log.Printf("[sop-roles] %s 绑定工具失败: %v", seed.key, err)
		}
		if err := s.m.pg.ToggleSkillVisibility(a.ID, seed.skill, true); err != nil {
			log.Printf("[sop-roles] %s 绑定 skill %s 失败: %v", seed.key, seed.skill, err)
		}
		log.Printf("[sop-roles] 已预置「%s」agent + 工具/skill 绑定", seed.name)
	}
}
