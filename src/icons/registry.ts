/**
 * The single source of truth for icons (D6).
 *
 * Each icon is a list of primitive shapes rather than an SVG string, so `AppIcon.vue` can render
 * it with plain template markup — no `v-html`, no string concatenation, and one place to change
 * a glyph. Every icon is drawn on the same 24×24 grid with `fill="none"` and
 * `stroke="currentColor"`, so colour and stroke weight come from CSS.
 */

/**
 * One SVG primitive. Deliberately a flat record rather than a discriminated union: the renderer
 * is a plain template, and a union would force type narrowing inside it for no benefit. An
 * irrelevant field is simply absent, and Vue drops the attribute when the value is `undefined`.
 */
export interface IconShape {
  t: 'path' | 'circle' | 'line' | 'polyline' | 'rect';
  d?: string;
  cx?: number;
  cy?: number;
  r?: number;
  x1?: number;
  y1?: number;
  x2?: number;
  y2?: number;
  points?: string;
  x?: number;
  y?: number;
  width?: number;
  height?: number;
  rx?: number;
}

const icons = {
  /* -- brand ------------------------------------------------------------------------------ */
  brand: [
    { t: 'path', d: 'M12 3 4.5 20h15L12 3z' },
    { t: 'path', d: 'M12 9 8.5 17h7L12 9z' },
  ],

  /* -- navigation ------------------------------------------------------------------------ */
  wifi: [
    { t: 'path', d: 'M5 12.55a11 11 0 0 1 14.08 0' },
    { t: 'path', d: 'M1.42 9a16 16 0 0 1 21.16 0' },
    { t: 'path', d: 'M8.53 16.11a6 6 0 0 1 6.95 0' },
    { t: 'line', x1: 12, y1: 20, x2: 12.01, y2: 20 },
  ],
  sliders: [
    { t: 'line', x1: 4, y1: 21, x2: 4, y2: 14 },
    { t: 'line', x1: 4, y1: 10, x2: 4, y2: 3 },
    { t: 'line', x1: 12, y1: 21, x2: 12, y2: 12 },
    { t: 'line', x1: 12, y1: 8, x2: 12, y2: 3 },
    { t: 'line', x1: 20, y1: 21, x2: 20, y2: 16 },
    { t: 'line', x1: 20, y1: 12, x2: 20, y2: 3 },
    { t: 'line', x1: 1, y1: 14, x2: 7, y2: 14 },
    { t: 'line', x1: 9, y1: 8, x2: 15, y2: 8 },
    { t: 'line', x1: 17, y1: 16, x2: 23, y2: 16 },
  ],
  settings: [
    { t: 'circle', cx: 12, cy: 12, r: 3 },
    {
      t: 'path',
      d: 'M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z',
    },
  ],
  'file-text': [
    { t: 'path', d: 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z' },
    { t: 'polyline', points: '14 2 14 8 20 8' },
    { t: 'line', x1: 16, y1: 13, x2: 8, y2: 13 },
    { t: 'line', x1: 16, y1: 17, x2: 8, y2: 17 },
    { t: 'polyline', points: '10 9 9 9 8 9' },
  ],

  /* -- window controls ------------------------------------------------------------------- */
  'window-minimize': [{ t: 'line', x1: 5, y1: 12, x2: 19, y2: 12 }],
  'window-maximize': [{ t: 'rect', x: 5, y: 5, width: 14, height: 14, rx: 2 }],
  'window-restore': [
    { t: 'rect', x: 4, y: 8, width: 12, height: 12, rx: 2 },
    { t: 'path', d: 'M8 8V6a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2h-2' },
  ],
  'window-close': [
    { t: 'line', x1: 6, y1: 6, x2: 18, y2: 18 },
    { t: 'line', x1: 18, y1: 6, x2: 6, y2: 18 },
  ],

  /* -- actions --------------------------------------------------------------------------- */
  refresh: [
    { t: 'polyline', points: '23 4 23 10 17 10' },
    { t: 'polyline', points: '1 20 1 14 7 14' },
    {
      t: 'path',
      d: 'M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15',
    },
  ],
  'play': [{ t: 'path', d: 'M6 4l14 8-14 8z' }],
  'stop': [{ t: 'rect', x: 6, y: 6, width: 12, height: 12, rx: 2 }],
  copy: [
    { t: 'rect', x: 9, y: 9, width: 13, height: 13, rx: 2 },
    { t: 'path', d: 'M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1' },
  ],
  clipboard: [
    { t: 'rect', x: 8, y: 3, width: 8, height: 4, rx: 1 },
    { t: 'path', d: 'M16 5h2a2 2 0 0 1 2 2v13a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h2' },
  ],
  check: [{ t: 'polyline', points: '20 6 9 17 4 12' }],
  plus: [
    { t: 'line', x1: 12, y1: 5, x2: 12, y2: 19 },
    { t: 'line', x1: 5, y1: 12, x2: 19, y2: 12 },
  ],
  trash: [
    { t: 'polyline', points: '3 6 5 6 21 6' },
    { t: 'path', d: 'M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6' },
    { t: 'path', d: 'M10 11v6M14 11v6' },
    { t: 'path', d: 'M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2' },
  ],
  search: [
    { t: 'circle', cx: 11, cy: 11, r: 7 },
    { t: 'line', x1: 16, y1: 16, x2: 21, y2: 21 },
  ],
  eye: [
    { t: 'path', d: 'M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7z' },
    { t: 'circle', cx: 12, cy: 12, r: 3 },
  ],
  'eye-off': [
    { t: 'path', d: 'M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94' },
    { t: 'path', d: 'M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19' },
    { t: 'path', d: 'M14.12 14.12a3 3 0 1 1-4.24-4.24' },
    { t: 'line', x1: 1, y1: 1, x2: 23, y2: 23 },
  ],
  'chevron-down': [{ t: 'polyline', points: '6 9 12 15 18 9' }],
  'chevron-right': [{ t: 'polyline', points: '9 18 15 12 9 6' }],
  'chevron-left': [{ t: 'polyline', points: '15 18 9 12 15 6' }],
  'arrow-up': [
    { t: 'line', x1: 12, y1: 19, x2: 12, y2: 5 },
    { t: 'polyline', points: '5 12 12 5 19 12' },
  ],
  'external-link': [
    { t: 'path', d: 'M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6' },
    { t: 'polyline', points: '15 3 21 3 21 9' },
    { t: 'line', x1: 10, y1: 14, x2: 21, y2: 3 },
  ],

  /* -- link type: two peers and the path between them ------------------------------------- */
  // Drawn as a pair on purpose: the extra hollow node in the middle *is* the difference between
  // a direct connection and a relayed one, which no generic globe or arrow icon conveys.
  'link-direct': [
    { t: 'circle', cx: 4, cy: 12, r: 2 },
    { t: 'circle', cx: 20, cy: 12, r: 2 },
    { t: 'line', x1: 7, y1: 12, x2: 17, y2: 12 },
  ],
  'link-relay': [
    { t: 'circle', cx: 4, cy: 12, r: 2 },
    { t: 'circle', cx: 20, cy: 12, r: 2 },
    { t: 'circle', cx: 12, cy: 12, r: 1.6 },
    { t: 'line', x1: 7, y1: 12, x2: 10.2, y2: 12 },
    { t: 'line', x1: 13.8, y1: 12, x2: 17, y2: 12 },
  ],
  // Broken line: connected, but no path has been selected yet.
  'link-unknown': [
    { t: 'circle', cx: 4, cy: 12, r: 2 },
    { t: 'circle', cx: 20, cy: 12, r: 2 },
    { t: 'line', x1: 8, y1: 12, x2: 10, y2: 12 },
    { t: 'line', x1: 14, y1: 12, x2: 16, y2: 12 },
  ],

  /* -- status ---------------------------------------------------------------------------- */
  'alert-triangle': [
    {
      t: 'path',
      d: 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z',
    },
  ],
  'alert-circle': [
    { t: 'circle', cx: 12, cy: 12, r: 10 },
    { t: 'line', x1: 12, y1: 8, x2: 12, y2: 12 },
    { t: 'line', x1: 12, y1: 16, x2: 12.01, y2: 16 },
  ],
  info: [
    { t: 'circle', cx: 12, cy: 12, r: 10 },
    { t: 'line', x1: 12, y1: 16, x2: 12, y2: 12 },
    { t: 'line', x1: 12, y1: 8, x2: 12.01, y2: 8 },
  ],

  /* -- appearance / language -------------------------------------------------------------- */
  monitor: [
    { t: 'rect', x: 2, y: 3, width: 20, height: 14, rx: 2 },
    { t: 'line', x1: 8, y1: 21, x2: 16, y2: 21 },
    { t: 'line', x1: 12, y1: 17, x2: 12, y2: 21 },
  ],
  sun: [
    { t: 'circle', cx: 12, cy: 12, r: 4 },
    { t: 'path', d: 'M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41' },
  ],
  moon: [
    { t: 'path', d: 'M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z' },
  ],
  globe: [
    { t: 'circle', cx: 12, cy: 12, r: 10 },
    { t: 'line', x1: 2, y1: 12, x2: 22, y2: 12 },
    { t: 'path', d: 'M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z' },
  ],

  /* -- fallback --------------------------------------------------------------------------- */
  circle: [{ t: 'circle', cx: 12, cy: 12, r: 10 }],
} satisfies Record<string, IconShape[]>;

export type IconName = keyof typeof icons;

export const ICONS = icons;

export function getIconShapes(name: string): IconShape[] {
  return (icons as Record<string, IconShape[]>)[name] ?? icons.circle;
}
