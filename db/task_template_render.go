package db

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

const MaxTaskTemplateVariableRunes = 4000

var (
	ErrTaskTemplateRender = errors.New("task template render failed")
	taskTemplateNameRE    = regexp.MustCompile(`^[\p{L}_][\p{L}\p{N}_]{0,63}$`)
	taskTemplateSlotRE    = regexp.MustCompile(`\{\{\s*([\p{L}_][\p{L}\p{N}_]{0,63})\s*\}\}`)
)

type RenderedTaskTemplate struct {
	Description string
	Goal        string
	Remark      string
}

func RenderTaskTemplate(template TaskTemplate, variables map[string]string) (RenderedTaskTemplate, error) {
	var out RenderedTaskTemplate
	fields := []struct {
		name  string
		text  string
		limit int
	}{
		{name: "description", text: template.Description, limit: MaxTaskTemplateTextRunes},
		{name: "goal", text: template.Goal, limit: MaxTaskTemplateTextRunes},
		{name: "remark", text: template.Remark, limit: MaxTaskRemarkRunes},
	}

	required := map[string]struct{}{}
	for _, field := range fields {
		remainder := taskTemplateSlotRE.ReplaceAllString(field.text, "")
		if strings.Contains(remainder, "{{") || strings.Contains(remainder, "}}") {
			return out, fmt.Errorf("%w: %s contains a malformed placeholder", ErrTaskTemplateRender, field.name)
		}
		for _, match := range taskTemplateSlotRE.FindAllStringSubmatch(field.text, -1) {
			required[match[1]] = struct{}{}
		}
	}

	normalized := make(map[string]string, len(variables))
	for name, value := range variables {
		if !taskTemplateNameRE.MatchString(name) {
			return out, fmt.Errorf("%w: invalid variable name %q", ErrTaskTemplateRender, name)
		}
		if _, ok := required[name]; !ok {
			return out, fmt.Errorf("%w: unknown variable %q", ErrTaskTemplateRender, name)
		}
		value = strings.TrimSpace(value)
		if value == "" {
			return out, fmt.Errorf("%w: variable %s must not be empty", ErrTaskTemplateRender, name)
		}
		if utf8.RuneCountInString(value) > MaxTaskTemplateVariableRunes {
			return out, fmt.Errorf("%w: variable %s exceeds %d characters", ErrTaskTemplateRender, name, MaxTaskTemplateVariableRunes)
		}
		normalized[name] = value
	}

	missing := make([]string, 0)
	for name := range required {
		if _, ok := normalized[name]; !ok {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return out, fmt.Errorf("%w: missing variables: %s", ErrTaskTemplateRender, strings.Join(missing, ", "))
	}

	rendered := make([]string, len(fields))
	for i, field := range fields {
		rendered[i] = taskTemplateSlotRE.ReplaceAllStringFunc(field.text, func(slot string) string {
			name := taskTemplateSlotRE.FindStringSubmatch(slot)[1]
			return normalized[name]
		})
		if utf8.RuneCountInString(rendered[i]) > field.limit {
			return out, fmt.Errorf("%w: rendered %s exceeds %d characters", ErrTaskTemplateRender, field.name, field.limit)
		}
	}
	out.Description = rendered[0]
	out.Goal = rendered[1]
	out.Remark = rendered[2]
	return out, nil
}
