/**
 * Source-text helpers shared by the lint scripts.
 *
 * `stripComments` exists because both checks are textual, and a comment is not code. A doc example
 * such as `t('settings.uninstallService')`, or a palette value quoted inside an explanatory
 * comment, would otherwise be reported as a violation — a failure nobody can fix, which is how a
 * linter gets switched off instead of obeyed.
 *
 * It is deliberately not a parser. It understands just enough to avoid the mistakes that matter:
 * `//` inside a URL is not a comment, an escape sequence does not end a string, and a block
 * comment does not end at the first line that happens to start with `*`.
 *
 * Blanking rather than deleting is intentional: the result has the same length and the same number
 * of newlines as the input, so byte offsets and reported line numbers stay correct.
 */
export function stripComments(source) {
  let out = '';
  let quote = null;
  let i = 0;
  const n = source.length;

  while (i < n) {
    const char = source[i];
    const next = source[i + 1];

    if (quote) {
      out += char;
      if (char === '\\') {
        out += next ?? '';
        i += 2;
        continue;
      }
      if (char === quote) quote = null;
      i += 1;
      continue;
    }

    if (char === '"' || char === "'" || char === '`') {
      quote = char;
      out += char;
      i += 1;
      continue;
    }

    if (char === '/' && next === '*') {
      const end = source.indexOf('*/', i + 2);
      const body = end === -1 ? source.slice(i) : source.slice(i, end + 2);
      out += body.replace(/[^\n]/g, ' ');
      i = end === -1 ? n : end + 2;
      continue;
    }

    if (char === '/' && next === '/') {
      // Guard against `https://` and the like: `//` only starts a comment when it is not part of a
      // scheme, which in practice means "not preceded by a colon".
      if (source[i - 1] !== ':') {
        const end = source.indexOf('\n', i);
        const stop = end === -1 ? n : end;
        out += ' '.repeat(stop - i);
        i = stop;
        continue;
      }
    }

    out += char;
    i += 1;
  }

  return out;
}
