import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
require("ts-node").register({
  transpileOnly: true,
  compilerOptions: { module: "CommonJS", moduleResolution: "Node10" },
});
const {
  buildTaskTemplateCreatePayload,
  reconcileAppliedTaskTemplate,
  taskTemplateFormFields,
} = require("./task-template-state.ts");
const { taskTemplateVariableNames } = require("./types.ts");

const template = (id, description, goal, extra = {}) => ({
  id,
  name: `template-${id}`,
  description,
  goal,
  remark: "",
  created_at: "2026-11-07T00:00:00Z",
  updated_at: "2026-11-07T00:00:00Z",
  ...extra,
});

test("editing the applied template refreshes every form field and reconciles variables", () => {
  const original = template(7, "检查 {{old}} 与 {{shared}}", "验证 {{shared}}", {
    remark: "旧备注 {{old}}",
    category_id: 1,
    worker_count: 2,
    intercept_rules: [{ pattern: "old.example", action: "block" }],
  });
  const edited = template(7, "检查 {{added}} 与 {{shared}}", "验证 {{added}}", {
    remark: "新备注 {{added}}",
    category_id: 2,
    worker_count: 4,
    intercept_rules: [{ pattern: "added.example", action: "allow" }],
  });
  const synced = reconcileAppliedTaskTemplate(
    original,
    edited,
    { old: "remove-me", shared: "keep-me" },
    taskTemplateFormFields(original),
  );

  assert.equal(synced.template, edited);
  assert.deepEqual(taskTemplateVariableNames(synced.template), ["added", "shared"]);
  assert.deepEqual(synced.variables, { added: "", shared: "keep-me" });
  assert.deepEqual(synced.fields, {
    description: "检查 {{added}} 与 {{shared}}",
    goal: "验证 {{added}}",
    remark: "新备注 {{added}}",
    categoryID: 2,
    workerCount: "4",
    interceptRules: [{ pattern: "added.example", action: "allow" }],
  });
});

test("updated template creation payload contains only current values and deliberate local overrides", () => {
  const original = template(7, "检查 {{old}} 与 {{shared}}", "验证 {{shared}}", {
    remark: "旧备注 {{old}}",
    category_id: 1,
    worker_count: 2,
    intercept_rules: [{ pattern: "old.example", action: "block" }],
  });
  const edited = template(7, "检查 {{added}} 与 {{shared}}", "验证 {{added}}", {
    remark: "新备注",
    category_id: 2,
    worker_count: 4,
    intercept_rules: [{ pattern: "added.example", action: "allow" }],
  });
  const synced = reconcileAppliedTaskTemplate(
    original,
    edited,
    { old: "remove-me", shared: "keep-me" },
    taskTemplateFormFields(original),
  );
  const variables = { added: "added.example", shared: "shared.example" };

  assert.deepEqual(buildTaskTemplateCreatePayload(synced.template, variables, synced.fields, 4), {
    description: "检查 {{added}} 与 {{shared}}",
    goal: "验证 {{added}}",
    remark: "新备注",
    categoryId: 2,
    templateId: 7,
    templateVariables: { added: "added.example", shared: "shared.example" },
    templateOverrides: undefined,
    workerCount: 4,
    interceptRules: [{ pattern: "added.example", action: "allow" }],
  });

  const payload = buildTaskTemplateCreatePayload(
    synced.template,
    variables,
    {
      ...synced.fields,
      description: "本地修订描述",
      workerCount: "7",
      interceptRules: [{ pattern: " local.example ", action: "block" }],
    },
    7,
  );
  assert.deepEqual(payload, {
    description: "本地修订描述",
    goal: "验证 {{added}}",
    remark: "新备注",
    categoryId: 2,
    templateId: 7,
    templateVariables: { added: "added.example", shared: "shared.example" },
    templateOverrides: {
      description: "本地修订描述",
      worker_count: 7,
      intercept_rules: [{ pattern: "local.example", action: "block" }],
    },
    workerCount: 7,
    interceptRules: [{ pattern: "local.example", action: "block" }],
  });
  assert.equal(JSON.stringify(payload).includes("{{old}}"), false);
  assert.equal(JSON.stringify(payload).includes("remove-me"), false);
});

test("editing another template does not disturb the applied snapshot, variables, or form fields", () => {
  const applied = template(7, "检查 {{target}}", "验证 {{target}}");
  const variables = { target: "example.test" };
  const fields = taskTemplateFormFields(applied);
  const synced = reconcileAppliedTaskTemplate(
    applied,
    template(8, "其他 {{other}}", "其他 {{other}}"),
    variables,
    fields,
  );

  assert.equal(synced.template, applied);
  assert.equal(synced.variables, variables);
  assert.equal(synced.fields, fields);
});
