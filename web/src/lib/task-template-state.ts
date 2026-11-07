import {
  taskTemplateVariableNames,
  type AssetInterceptRuleInput,
  type TaskTemplate,
  type TaskTemplateOverrides,
} from "./types";

export interface TaskTemplateFormFields {
  description: string;
  goal: string;
  remark: string;
  categoryID: number | undefined;
  workerCount: string;
  interceptRules: AssetInterceptRuleInput[];
}

export interface TaskTemplateCreatePayload {
  description: string;
  goal: string;
  remark: string;
  categoryId: number | undefined;
  templateId: number | undefined;
  templateVariables: Record<string, string> | undefined;
  templateOverrides: TaskTemplateOverrides | undefined;
  workerCount: number;
  interceptRules: AssetInterceptRuleInput[];
}

export function taskTemplateFormFields(template: TaskTemplate): TaskTemplateFormFields {
  return {
    description: template.description,
    goal: template.goal,
    remark: template.remark ?? "",
    categoryID: template.category_id ?? undefined,
    workerCount: template.worker_count ? String(template.worker_count) : "",
    interceptRules: template.intercept_rules ?? [],
  };
}

export function reconcileAppliedTaskTemplate(
  applied: TaskTemplate | null,
  updated: TaskTemplate,
  variables: Record<string, string>,
  fields: TaskTemplateFormFields,
): { template: TaskTemplate | null; variables: Record<string, string>; fields: TaskTemplateFormFields } {
  if (applied?.id !== updated.id) return { template: applied, variables, fields };
  const nextVariables: Record<string, string> = {};
  for (const name of taskTemplateVariableNames(updated)) {
    nextVariables[name] = variables[name] ?? "";
  }
  return { template: updated, variables: nextVariables, fields: taskTemplateFormFields(updated) };
}

export function buildTaskTemplateCreatePayload(
  appliedTemplate: TaskTemplate | null,
  variables: Record<string, string>,
  fields: TaskTemplateFormFields,
  workerCount: number,
): TaskTemplateCreatePayload {
  const interceptRules = fields.interceptRules
    .map((rule) => ({ ...rule, pattern: rule.pattern.trim() }))
    .filter((rule) => rule.pattern !== "");
  let templateOverrides: TaskTemplateOverrides | undefined;
  if (appliedTemplate) {
    const overrides: TaskTemplateOverrides = {};
    const description = fields.description.trim();
    const goal = fields.goal.trim();
    const remark = fields.remark.trim();
    if (description !== appliedTemplate.description) overrides.description = description;
    if (goal !== appliedTemplate.goal) overrides.goal = goal;
    if (remark !== (appliedTemplate.remark ?? "")) overrides.remark = remark;
    if ((fields.categoryID ?? null) !== (appliedTemplate.category_id ?? null)) {
      overrides.category_id = fields.categoryID ?? null;
    }
    if (workerCount !== (appliedTemplate.worker_count ?? 0)) overrides.worker_count = workerCount;
    if (JSON.stringify(interceptRules) !== JSON.stringify(appliedTemplate.intercept_rules ?? [])) {
      overrides.intercept_rules = interceptRules;
    }
    if (Object.keys(overrides).length > 0) templateOverrides = overrides;
  }
  return {
    description: fields.description.trim(),
    goal: fields.goal.trim(),
    remark: fields.remark.trim(),
    categoryId: fields.categoryID,
    templateId: appliedTemplate?.id,
    templateVariables: appliedTemplate ? variables : undefined,
    templateOverrides,
    workerCount,
    interceptRules,
  };
}
