#!/usr/bin/env node
/**
 * Design-token guard (docs/ui-refactor-plan.md §5.9).
 *
 * Three checks:
 *   1. Every `var(--x)` reference in `src/` must have a definition somewhere in `src/styles/`.
 *      The pre-refactor codebase referenced tokens that were never declared, so the declarations
 *      silently dropped and the page rendered with inherited colours (D3).
 *   2. No component may declare a raw hex colour: colours come from semantic tokens, otherwise the
 *      theme cannot follow (§4.3).
 *   3. No component may declare a literal `font-family`: the per-OS CJK stacks are declared once as
 *      `--font-sans` / `--font-mono` (§5.11 rule 3, D15). Reading the token —
 *      `font-family: var(--font-mono)` — is the correct usage and is not a violation.
 *
 * `src/styles/*.css` is the token layer, where raw values are allowed to live.
 *
 * Quarantine: the files still scheduled for rewrite or deletion (Phase 3 pages, Phase 4 component
 * removal) are listed in `LEGACY_EXEMPT`. Their violations are counted and reported, but do not
 * fail the build — a linter that is red on the day it is installed gets switched off. The count is
 * the progress metric: it must reach zero, at which point the list itself is deleted.
 *
 * Exits 0 with a notice when `src/styles` does not exist yet.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { stripComments } from './lib/source.mjs';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const srcDir = join(root, 'src');
const stylesDir = join(srcDir, 'styles');

/** Files still on the chopping block. Each entry goes away in the phase named next to it. */
const LEGACY_EXEMPT = new Set([
  // Phase 3.1–3.4
  'src/pages/DashboardPage.vue',
  'src/pages/ConfigPage.vue',
  'src/pages/SettingsPage.vue',
  'src/pages/LogsPage.vue',
  // Phase 4 — replaced by ToastHost / AppDialog / domain components
  'src/components/Toast.vue',
  'src/components/ConfirmDialog.vue',
  'src/components/ServiceManager.vue',
  'src/components/ProxyStatusControl.vue',
]);

function read(path) {
  try {
    return readFileSync(path, 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}

function walk(dir, out = []) {
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) walk(path, out);
    else if (/\.(vue|css|ts)$/.test(entry)) out.push(path);
  }
  return out;
}

/** Every `.css` directly under `src/styles/` is part of the token layer. */
function readStyleSources() {
  try {
    return readdirSync(stylesDir)
      .filter((entry) => entry.endsWith('.css'))
      .map((entry) => read(join(stylesDir, entry)))
      .filter((source) => source !== null);
  } catch (error) {
    if (error.code === 'ENOENT') return [];
    throw error;
  }
}

const styleSources = readStyleSources();
if (styleSources.length === 0) {
  console.log('[lint:tokens] src/styles not present yet — skipping (see plan §4)');
  process.exit(0);
}

const declared = new Set();
for (const source of styleSources) {
  for (const match of stripComments(source).matchAll(/(--[\w-]+)\s*:/g)) declared.add(match[1]);
}

const problems = [];
const undefinedTokens = new Map();
const quarantined = [];
const outsideTokenLayer = [];

for (const file of walk(srcDir)) {
  const rel = relative(root, file).replace(/\\/g, '/');
  const source = stripComments(readFileSync(file, 'utf8'));
  const isStyleLayer = rel.startsWith('src/styles/');
  const exempt = LEGACY_EXEMPT.has(rel);

  for (const match of source.matchAll(/var\(\s*(--[\w-]+)/g)) {
    const token = match[1];
    if (!declared.has(token)) {
      if (!undefinedTokens.has(token)) undefinedTokens.set(token, new Set());
      undefinedTokens.get(token).add(rel);
    }
  }

  if (isStyleLayer) continue;

  const violations = [];

  source.split('\n').forEach((line, index) => {
    for (const match of line.matchAll(/#[0-9a-fA-F]{3,8}\b/g)) {
      violations.push(`${rel}:${index + 1}  raw hex ${match[0]}`);
    }

    const declaration = line.match(/font-family\s*:\s*([^;}]+)/);
    // `var(--font-mono)` is the pattern the rule exists to encourage; only a literal stack is a
    // violation.
    if (declaration && !/var\(\s*--font-/.test(declaration[1])) {
      violations.push(`${rel}:${index + 1}  literal font-family ${declaration[1].trim()}`);
    }
  });

  if (violations.length === 0) continue;
  if (exempt) quarantined.push(...violations);
  else problems.push(...violations);
}

if (undefinedTokens.size) {
  const lines = [...undefinedTokens.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([token, files]) => `${token}  (${[...files].join(', ')})`);
  problems.push(
    `var() references with no definition (${undefinedTokens.size}):\n  ${lines.join('\n  ')}`,
  );
}
if (outsideTokenLayer.length) {
  problems.push(
    `raw values outside the token layer (${outsideTokenLayer.length}):\n  ${outsideTokenLayer.join('\n  ')}`,
  );
}
if (problems.length) {
  console.error(`[lint:tokens] FAILED\n\n${problems.join('\n\n')}\n`);
  process.exit(1);
}

console.log(
  `[lint:tokens] ok — ${declared.size} tokens declared, no raw values outside src/styles/`,
);

if (quarantined.length) {
  const files = new Set(quarantined.map((line) => line.split(':')[0]));
  console.log(
    `[lint:tokens] quarantined: ${quarantined.length} known violation(s) in ${files.size} ` +
      `file(s) awaiting rewrite — ${[...files].sort().join(', ')}`,
  );
}
