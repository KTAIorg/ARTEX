package server

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Autumn-27/artex/db"
)

type taskTemplateOverrides struct {
	Description    *string                 `json:"description"`
	Goal           *string                 `json:"goal"`
	Remark         *string                 `json:"remark"`
	CategoryID     *int64                  `json:"category_id"`
	InterceptRules *[]taskInterceptRuleReq `json:"intercept_rules"`
	WorkerCount    *int                    `json:"worker_count"`
	setCategoryID  bool
}

func (o *taskTemplateOverrides) UnmarshalJSON(data []byte) error {
	type overridesAlias taskTemplateOverrides
	var decoded overridesAlias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	var present map[string]json.RawMessage
	if err := json.Unmarshal(data, &present); err != nil {
		return err
	}
	*o = taskTemplateOverrides(decoded)
	_, o.setCategoryID = present["category_id"]
	return nil
}

func applyTaskTemplate(pg *db.DB, req *createTaskReq) error {
	if req.TemplateID == nil {
		if len(req.TemplateVariables) > 0 || req.TemplateOverrides != nil {
			return fmt.Errorf("%w: template_id is required with template variables or overrides", db.ErrTaskTemplateInvalid)
		}
		return nil
	}
	if *req.TemplateID <= 0 {
		return fmt.Errorf("%w: template_id must be positive", db.ErrTaskTemplateInvalid)
	}
	template, err := pg.GetTaskTemplate(*req.TemplateID)
	if err != nil {
		return err
	}
	if template == nil {
		return db.ErrTaskTemplateNotFound
	}
	rendered, err := db.RenderTaskTemplate(*template, req.TemplateVariables)
	if err != nil {
		return err
	}
	req.Description = rendered.Description
	req.Goal = rendered.Goal
	req.Remark = rendered.Remark
	req.CategoryID = template.CategoryID
	req.WorkerCount = template.WorkerCount
	req.InterceptRules = make([]taskInterceptRuleReq, 0, len(template.InterceptRules))
	for _, rule := range template.InterceptRules {
		req.InterceptRules = append(req.InterceptRules, taskInterceptRuleReq{
			Enabled: rule.Enabled,
			Action:  rule.Action,
			Kind:    rule.Kind,
			Pattern: rule.Pattern,
			Note:    rule.Note,
		})
	}

	overrides := req.TemplateOverrides
	if overrides == nil {
		return nil
	}
	if overrides.Description != nil {
		req.Description = strings.TrimSpace(*overrides.Description)
		if req.Description == "" {
			return fmt.Errorf("%w: description override must not be empty", db.ErrTaskTemplateInvalid)
		}
	}
	if overrides.Goal != nil {
		req.Goal = strings.TrimSpace(*overrides.Goal)
		if req.Goal == "" {
			return fmt.Errorf("%w: goal override must not be empty", db.ErrTaskTemplateInvalid)
		}
	}
	if overrides.Remark != nil {
		req.Remark = *overrides.Remark
	}
	if overrides.setCategoryID {
		req.CategoryID = overrides.CategoryID
	}
	if overrides.InterceptRules != nil {
		req.InterceptRules = *overrides.InterceptRules
	}
	if overrides.WorkerCount != nil {
		req.WorkerCount = *overrides.WorkerCount
	}
	return nil
}
