#!/usr/bin/env node
// 构建产物品牌词清洗（issue #61 A5）。
//
// 背景：即使 sourcemap 关了，next build 产出的 .next/static/**/*.js 里仍会留下
// 产品名、内部描述等字符串——公网部署时，任何人下载 bundle 搜一下就能确认这是
// 哪套系统。这里在 build 之后做一次扫描 + 替换，并对残留做失败断言。
//
// 用法：node scripts/clean-build-strings.mjs [distDir]（默认 .next）
// 退出码：0 干净；1 仍有残留（CI 应当挂掉）。

import { readdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

const DIST = process.argv[2] ?? ".next";
// 只清洗"可被外部下载"的产物；server 侧编译产物里的内部注释不动。
const TARGET_DIRS = ["static"];
const REPLACEMENTS = [
  [/ARTEX/gi, "Workbench"],
  [/自主渗透测试系统/g, "任务工作台"],
  [/自主渗透测试控制台/g, "任务与数据工作台"],
  [/LLM 驱动的自主渗透测试/g, "AI 驱动的工作流"],
];
// 断言用：清洗后这些词不允许再出现（大小写不敏感）。
const FORBIDDEN = ["ARTEX", "自主渗透", "渗透测试控制台"];

async function* walk(dir) {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) yield* walk(p);
    else if (e.isFile() && /\.(js|css|map|json|html)$/.test(e.name)) yield p;
  }
}

const files = [];
for (const d of TARGET_DIRS) {
  for await (const f of walk(path.join(DIST, d))) files.push(f);
}

let changed = 0;
for (const f of files) {
  const raw = await readFile(f, "utf8");
  let out = raw;
  for (const [re, to] of REPLACEMENTS) out = out.replace(re, to);
  if (out !== raw) {
    await writeFile(f, out, "utf8");
    changed++;
  }
}

const hits = [];
for (const f of files) {
  const txt = (await readFile(f, "utf8")).toLowerCase();
  for (const word of FORBIDDEN) {
    if (txt.includes(word.toLowerCase())) hits.push(`${f} ← ${word}`);
  }
}

console.log(`[clean-build] 扫描 ${files.length} 个产物，改写 ${changed} 个`);
if (hits.length) {
  console.error(`[clean-build] 仍有品牌词残留（${hits.length}）：`);
  for (const h of hits.slice(0, 20)) console.error(`  ${h}`);
  process.exit(1);
}
console.log("[clean-build] 无残留 ✓");
