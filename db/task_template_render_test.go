package db

import (
	"errors"
	"strings"
	"testing"
)

func TestRenderTaskTemplateIsReusableAndDoesNotMutateTemplate(t *testing.T) {
	template := TaskTemplate{
		Description: "验证 {{ target }} 的 {{cve_id}}；资产：{{资产}}",
		Goal:        "确认 {{cve_id}} 在 {{target}} 上的影响",
		Remark:      "重复目标：{{target}}",
	}
	first, err := RenderTaskTemplate(template, map[string]string{
		"target": " https://one.example ",
		"cve_id": "CVE-2026-0001",
		"资产":     "one.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.Description != "验证 https://one.example 的 CVE-2026-0001；资产：one.example" ||
		first.Goal != "确认 CVE-2026-0001 在 https://one.example 上的影响" ||
		first.Remark != "重复目标：https://one.example" {
		t.Fatalf("unexpected first render: %+v", first)
	}
	second, err := RenderTaskTemplate(template, map[string]string{
		"target": "https://two.example",
		"cve_id": "CVE-2026-0002",
		"资产":     "two.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(second.Description, "https://two.example") || !strings.Contains(second.Description, "CVE-2026-0002") {
		t.Fatalf("template was not independently reusable: %+v", second)
	}
	if template.Description != "验证 {{ target }} 的 {{cve_id}}；资产：{{资产}}" || template.Goal != "确认 {{cve_id}} 在 {{target}} 上的影响" {
		t.Fatalf("render mutated source template: %+v", template)
	}
}

func TestRenderTaskTemplateRejectsMissingUnknownAndMalformedVariables(t *testing.T) {
	template := TaskTemplate{Description: "target={{target}} cve={{cve_id}}", Goal: "verify {{target}}"}
	tests := []struct {
		name      string
		template  TaskTemplate
		variables map[string]string
		contains  string
	}{
		{name: "missing", template: template, variables: map[string]string{"target": "a"}, contains: "cve_id"},
		{name: "empty", template: template, variables: map[string]string{"target": "a", "cve_id": " "}, contains: "must not be empty"},
		{name: "unknown", template: template, variables: map[string]string{"target": "a", "cve_id": "CVE-2026-1", "extra": "x"}, contains: "unknown variable"},
		{name: "invalid name", template: template, variables: map[string]string{"target": "a", "cve_id": "CVE-2026-1", "bad-name": "x"}, contains: "invalid variable name"},
		{name: "unclosed", template: TaskTemplate{Description: "{{target", Goal: "goal"}, variables: map[string]string{}, contains: "malformed placeholder"},
		{name: "invalid slot", template: TaskTemplate{Description: "{{bad-name}}", Goal: "goal"}, variables: map[string]string{}, contains: "malformed placeholder"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := RenderTaskTemplate(test.template, test.variables)
			if !errors.Is(err, ErrTaskTemplateRender) || !strings.Contains(err.Error(), test.contains) {
				t.Fatalf("error = %v, want ErrTaskTemplateRender containing %q", err, test.contains)
			}
		})
	}
}

func TestRenderTaskTemplateRejectsOversizedRenderedText(t *testing.T) {
	_, err := RenderTaskTemplate(TaskTemplate{
		Description: "{{value}}",
		Goal:        "goal",
	}, map[string]string{"value": strings.Repeat("界", MaxTaskTemplateVariableRunes+1)})
	if !errors.Is(err, ErrTaskTemplateRender) || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized variable error = %v", err)
	}
}
