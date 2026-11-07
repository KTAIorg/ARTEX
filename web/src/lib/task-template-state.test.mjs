import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
require("ts-node").register({
  transpileOnly: true,
  compilerOptions: { module: "CommonJS", moduleResolution: "Node10" },
});
const { reconcileAppliedTaskTemplate } = require("./task-template-state.ts");
const { taskTemplateVariableNames } = require("./types.ts");

const template = (id, description, goal) => ({
  id,
  name: `template-${id}`,
  description,
  goal,
  remark: "",
  created_at: "2026-11-07T00:00:00Z",
  updated_at: "2026-11-07T00:00:00Z",
});

test("editing the applied template refreshes the creation baseline and reconciles variables", () => {
  const original = template(7, "检查 {{old}} 与 {{shared}}", "验证 {{shared}}");
  const edited = template(7, "检查 {{added}} 与 {{shared}}", "验证 {{shared}}");
  const synced = reconcileAppliedTaskTemplate(original, edited, {
    old: "remove-me",
    shared: "keep-me",
  });

  assert.equal(synced.template, edited);
  assert.deepEqual(taskTemplateVariableNames(synced.template), ["added", "shared"]);
  assert.deepEqual(synced.variables, { added: "", shared: "keep-me" });
});

test("editing another template does not disturb the applied snapshot or variables", () => {
  const applied = template(7, "检查 {{target}}", "验证 {{target}}");
  const variables = { target: "example.test" };
  const synced = reconcileAppliedTaskTemplate(
    applied,
    template(8, "其他 {{other}}", "其他 {{other}}"),
    variables,
  );

  assert.equal(synced.template, applied);
  assert.equal(synced.variables, variables);
});
