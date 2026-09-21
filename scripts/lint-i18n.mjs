#!/usr/bin/env node
/**
 * i18n guard (docs/ui-refactor-plan.md §5.9).
 *
 * Two checks, both hard failures:
 *   1. `en.json` and `zh-CN.json` must have identical key sets. `en` is the source of truth, so a
 *      key present in one and missing in the other is either an untranslated string or a stale
 *      translation.
 *   2. Every statically written `t('some.key')` in `src/` must resolve in `en.json`. Dynamic keys
 *      (template literals, variables, plurals built from a variable) are skipped — they cannot be
 *      checked statically and are covered by the manual sweep instead. Comments are stripped
 *      first, so documenting an example key in a doc comment is not a build failure.
 *
 * Exits 0 with a notice when the locale files do not exist yet, so the script can sit in
 * `package.json` before the i18n layer lands.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { stripComments } from './lib/source.mjs';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const localesDir = join(root, 'src', 'i18n', 'locales');
const srcDir = join(root, 'src');

function readJson(path) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw new Error(`failed to parse ${path}: ${error.message}`);
  }
}

function flatten(value, prefix = '') {
  const keys = [];
  for (const [key, child] of Object.entries(value)) {
    const path = prefix ? `${prefix}.${key}` : key;
    if (child !== null && typeof child === 'object' && !Array.isArray(child)) {
      keys.push(...flatten(child, path));
    } else {
      keys.push(path);
    }
  }
  return keys;
}

function walk(dir, out = []) {
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) {
      walk(path, out);
    } else if (/\.(vue|ts)$/.test(entry)) {
      out.push(path);
    }
  }
  return out;
}

const en = readJson(join(localesDir, 'en.json'));
const zh = readJson(join(localesDir, 'zh-CN.json'));

if (!en || !zh) {
  console.log('[lint:i18n] locale files not present yet — skipping (see plan §5.5)');
  process.exit(0);
}

const problems = [];

const enKeys = new Set(flatten(en));
const zhKeys = new Set(flatten(zh));

const missingInZh = [...enKeys].filter((key) => !zhKeys.has(key)).sort();
const missingInEn = [...zhKeys].filter((key) => !enKeys.has(key)).sort();

if (missingInZh.length) {
  problems.push(`missing in zh-CN.json (${missingInZh.length}):\n  ${missingInZh.join('\n  ')}`);
}
if (missingInEn.length) {
  problems.push(`missing in en.json (${missingInEn.length}):\n  ${missingInEn.join('\n  ')}`);
}

// `t('a.b')` / `t("a.b")` / `$t('a.b')` with a literal key only.
const callPattern = /(?<![\w.])\$?t\(\s*['"]([\w.-]+)['"]/g;
const unknown = new Map();

for (const file of walk(srcDir)) {
  const source = stripComments(readFileSync(file, 'utf8'));
  for (const match of source.matchAll(callPattern)) {
    const key = match[1];
    // pluralised calls pass `n`, but the key itself is still static; a key without a counter is
    // fine, a key with one is checked at base level too
    if (!enKeys.has(key)) {
      const where = relative(root, file).replace(/\\/g, '/');
      if (!unknown.has(key)) unknown.set(key, new Set());
      unknown.get(key).add(where);
    }
  }
}

if (unknown.size) {
  const lines = [...unknown.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, files]) => `${key}  (${[...files].join(', ')})`);
  problems.push(`t() calls with no key in en.json (${unknown.size}):\n  ${lines.join('\n  ')}`);
}

if (problems.length) {
  console.error(`[lint:i18n] FAILED\n\n${problems.join('\n\n')}\n`);
  process.exit(1);
}

console.log(`[lint:i18n] ok — ${enKeys.size} keys, en/zh-CN in sync`);
