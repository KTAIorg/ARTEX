import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
require("ts-node").register({
  transpileOnly: true,
  compilerOptions: { module: "CommonJS", moduleResolution: "Node10" },
});
const { mockHandle } = require("./handler.ts");

test("mock direct task creation rejects an empty description like the real backend", async () => {
  await assert.rejects(
    mockHandle("POST", "/tasks", JSON.stringify({ description: " \n ", goal: "验证目标" })),
    /description 为必填/,
  );
});

test("mock direct task creation rejects a missing goal like the real backend", async () => {
  await assert.rejects(
    mockHandle("POST", "/tasks", JSON.stringify({ description: "任务描述" })),
    /goal 为必填/,
  );
});
