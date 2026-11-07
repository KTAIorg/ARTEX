import { taskTemplateVariableNames, type TaskTemplate } from "./types";

export function reconcileAppliedTaskTemplate(
  applied: TaskTemplate | null,
  updated: TaskTemplate,
  variables: Record<string, string>,
): { template: TaskTemplate | null; variables: Record<string, string> } {
  if (applied?.id !== updated.id) return { template: applied, variables };
  const nextVariables: Record<string, string> = {};
  for (const name of taskTemplateVariableNames(updated)) {
    nextVariables[name] = variables[name] ?? "";
  }
  return { template: updated, variables: nextVariables };
}
