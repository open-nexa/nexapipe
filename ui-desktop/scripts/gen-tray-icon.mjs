#!/usr/bin/env node
/**
 * gen-tray-icon.mjs — rebuild the tray icon from the master art.
 *
 * Why this exists: `src-tauri/src/tray.rs` used to compile in
 * `icons/Square44x44Logo.png` for the tray. That file is part of Tauri's own
 * Windows Store logo set, so the app's always-on icon in the notification area
 * was the Tauri swirl rather than this project's mark. `icons/icon.png` and the
 * rest of the `Square*Logo.png` set are the same swirl — nothing in the bundle
 * refers to them, but they are what a tray icon is easiest to reach for.
 *
 * The app's own art (`icons/nexapipe.png`) cannot be used as it stands: it is
 * a 1258 px raster painted on an opaque navy-to-purple gradient, and a tray
 * icon that carries its own opaque square reads as a filled tile in a panel of
 * other flat glyphs.
 *
 * So the mark is separated from its background here: the artwork is neon on a
 * dark ground, and the brightest channel of a pixel says how much of the mark
 * it holds. That value becomes the alpha channel, and the colours are kept as
 * they are — which leaves a transparent icon of the neon shield, the keyhole
 * and the checkmark, and nothing else.
 *
 * The extraction runs at 256 px and the result is scaled down to 128 px
 * afterwards, in premultiplied alpha: averaging a one-pixel neon stroke into a
 * ten-pixel block would otherwise dim it past the threshold it was kept for.
 *
 * Dependencies: none beyond Node itself. `scripts/gen-icons.swift` builds the
 * macOS `.icns` and needs macOS to run; this one runs anywhere the frontend
 * builds, which is the point — the tray icon is what every platform's panel
 * shows, and it was the one asset nobody could regenerate.
 *
 * Usage:
 *   node scripts/gen-tray-icon.mjs [--size 128] [--threshold 85]
 * Run from `ui-desktop/`.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { crc32, deflateSync, inflateSync } from 'node:zlib';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const MASTER = join(root, 'src-tauri', 'icons', 'nexapipe.png');
const OUTPUT = join(root, 'src-tauri', 'icons', 'tray.png');

/** The size the tray icon is written at. Windows scales it down to the panel. */
const DEFAULT_SIZE = 128;

/**
 * The brightness below which a pixel is treated as background.
 *
 * The master's ground runs from roughly `#071e48` to `#1a1a3a`, so nothing
 * darker than this belongs to the mark.
 */
const DEFAULT_THRESHOLD = 85;

/** The brightness that is fully opaque. Above it the neon is at full strength. */
const FULL_ALPHA = 200;

function die(message) {
  process.stderr.write(`gen-tray-icon: error: ${message}\n`);
  process.exit(1);
}

/* -- PNG decoding ---------------------------------------------------------------------------- */

/**
 * Decodes a PNG into RGBA.
 *
 * Only what this repository's assets use is supported: 8 bits per channel,
 * no interlacing, and the grey / RGB / RGBA colour types. A palette image is
 * refused rather than guessed at.
 */
function decodePng(buffer) {
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  if (!buffer.subarray(0, 8).equals(signature)) die('not a PNG');

  let offset = 8;
  let width = 0;
  let height = 0;
  let depth = 0;
  let colorType = 0;
  let interlace = 0;
  const idat = [];

  while (offset < buffer.length) {
    const length = buffer.readUInt32BE(offset);
    const type = buffer.toString('ascii', offset + 4, offset + 8);
    const data = buffer.subarray(offset + 8, offset + 8 + length);
    if (type === 'IHDR') {
      width = data.readUInt32BE(0);
      height = data.readUInt32BE(4);
      depth = data[8];
      colorType = data[9];
      interlace = data[12];
    } else if (type === 'IDAT') {
      idat.push(data);
    } else if (type === 'IEND') {
      break;
    }
    offset += 12 + length;
  }

  if (depth !== 8) die(`unsupported bit depth ${depth}`);
  if (interlace !== 0) die('interlaced PNGs are not supported');
  const channels = { 0: 1, 2: 3, 6: 4 }[colorType];
  if (!channels) die(`unsupported colour type ${colorType}`);

  const raw = inflateSync(Buffer.concat(idat));
  const stride = width * channels;
  const scanlines = Buffer.alloc(height * stride);
  let pos = 0;

  for (let y = 0; y < height; y++) {
    const filter = raw[pos++];
    const line = raw.subarray(pos, pos + stride);
    pos += stride;
    const current = scanlines.subarray(y * stride, (y + 1) * stride);
    const previous = y > 0 ? scanlines.subarray((y - 1) * stride, y * stride) : null;

    for (let x = 0; x < stride; x++) {
      const left = x >= channels ? current[x - channels] : 0;
      const up = previous ? previous[x] : 0;
      const upLeft = previous && x >= channels ? previous[x - channels] : 0;
      let value = line[x];

      switch (filter) {
        case 0:
          break;
        case 1:
          value += left;
          break;
        case 2:
          value += up;
          break;
        case 3:
          value += (left + up) >> 1;
          break;
        case 4: {
          // Paeth: the predictor nearest the three neighbours.
          const p = left + up - upLeft;
          const pa = Math.abs(p - left);
          const pb = Math.abs(p - up);
          const pc = Math.abs(p - upLeft);
          value += pa <= pb && pa <= pc ? left : pb <= pc ? up : upLeft;
          break;
        }
        default:
          die(`unsupported filter ${filter}`);
      }
      current[x] = value & 0xff;
    }
  }

  // Into RGBA, whatever the source colour type was.
  const pixels = Buffer.alloc(width * height * 4);
  for (let i = 0, p = 0; i < width * height; i++, p += channels) {
    const target = i * 4;
    if (channels === 1) {
      pixels[target] = scanlines[p];
      pixels[target + 1] = scanlines[p];
      pixels[target + 2] = scanlines[p];
      pixels[target + 3] = 255;
    } else if (channels === 3) {
      pixels[target] = scanlines[p];
      pixels[target + 1] = scanlines[p + 1];
      pixels[target + 2] = scanlines[p + 2];
      pixels[target + 3] = 255;
    } else {
      pixels[target] = scanlines[p];
      pixels[target + 1] = scanlines[p + 1];
      pixels[target + 2] = scanlines[p + 2];
      pixels[target + 3] = scanlines[p + 3];
    }
  }

  return { width, height, pixels };
}

/* -- PNG encoding ---------------------------------------------------------------------------- */

function chunk(type, data) {
  const head = Buffer.from(type, 'ascii');
  const out = Buffer.alloc(data.length + 12);
  out.writeUInt32BE(data.length, 0);
  head.copy(out, 4);
  data.copy(out, 8);
  out.writeUInt32BE(crc32(Buffer.concat([head, data])) >>> 0, data.length + 8);
  return out;
}

/** Writes RGBA pixels as an 8-bit RGBA PNG, every scanline unfiltered. */
function encodePng(width, height, pixels) {
  const stride = width * 4;
  const raw = Buffer.alloc(height * (stride + 1));
  for (let y = 0; y < height; y++) {
    raw[y * (stride + 1)] = 0; // filter: none
    pixels.copy(raw, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
  }

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // colour type: RGBA
  ihdr[10] = 0; // compression: deflate
  ihdr[11] = 0; // filter method
  ihdr[12] = 0; // interlace: none

  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

/* -- resampling ------------------------------------------------------------------------------ */

/**
 * Scales RGBA pixels down by averaging the source pixels that fall into each
 * target pixel.
 *
 * The average is taken in premultiplied alpha and divided back out afterwards:
 * averaging a transparent pixel with an opaque one without premultiplying
 * would pull the opaque pixel's colour towards black wherever the two meet.
 */
function downscale(pixels, sourceWidth, sourceHeight, targetWidth, targetHeight) {
  const out = Buffer.alloc(targetWidth * targetHeight * 4);
  const xRatio = sourceWidth / targetWidth;
  const yRatio = sourceHeight / targetHeight;

  for (let y = 0; y < targetHeight; y++) {
    const y0 = Math.floor(y * yRatio);
    const y1 = Math.min(sourceHeight, Math.max(y0 + 1, Math.ceil((y + 1) * yRatio)));

    for (let x = 0; x < targetWidth; x++) {
      const x0 = Math.floor(x * xRatio);
      const x1 = Math.min(sourceWidth, Math.max(x0 + 1, Math.ceil((x + 1) * xRatio)));

      let red = 0;
      let green = 0;
      let blue = 0;
      let alpha = 0;
      let count = 0;

      for (let sy = y0; sy < y1; sy++) {
        for (let sx = x0; sx < x1; sx++) {
          const i = (sy * sourceWidth + sx) * 4;
          const a = pixels[i + 3] / 255;
          red += pixels[i] * a;
          green += pixels[i + 1] * a;
          blue += pixels[i + 2] * a;
          alpha += pixels[i + 3];
          count++;
        }
      }

      const target = (y * targetWidth + x) * 4;
      const meanAlpha = alpha / count;
      if (meanAlpha === 0) {
        out[target] = 0;
        out[target + 1] = 0;
        out[target + 2] = 0;
        out[target + 3] = 0;
        continue;
      }
      const scale = 255 / alpha;
      out[target] = Math.min(255, Math.round(red * scale));
      out[target + 1] = Math.min(255, Math.round(green * scale));
      out[target + 2] = Math.min(255, Math.round(blue * scale));
      out[target + 3] = Math.round(meanAlpha);
    }
  }

  return out;
}

/* -- the icon -------------------------------------------------------------------------------- */

/**
 * Turns the mark's brightness into its alpha, keeping the colours.
 *
 * The brightest channel of a pixel is what says how much of the neon is in
 * it: the ground is dark in every channel, the mark is not. Anything below the
 * threshold is background and is dropped; anything above it is opaque.
 */
function extractMark(pixels, threshold) {
  const span = FULL_ALPHA - threshold;
  for (let i = 0; i < pixels.length; i += 4) {
    const brightness = Math.max(pixels[i], pixels[i + 1], pixels[i + 2]);
    const extracted = Math.max(0, Math.min(255, Math.round(((brightness - threshold) * 255) / span)));
    pixels[i + 3] = Math.round((pixels[i + 3] * extracted) / 255);
  }
  return pixels;
}

/* -- main ------------------------------------------------------------------------------------ */

function parseArguments() {
  const options = { size: DEFAULT_SIZE, threshold: DEFAULT_THRESHOLD };
  const args = process.argv.slice(2);
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--size' || arg === '--threshold') {
      const value = Number(args[++i]);
      if (!Number.isFinite(value) || value <= 0) die(`${arg} needs a positive number`);
      // The extraction maps brightness onto alpha over the span between the
      // threshold and full opacity. A threshold at or above that point leaves no
      // span to divide by, and one above it inverts the mapping: the background
      // becomes opaque and the mark becomes transparent. Either way the script
      // would write a blank or inverted icon and exit zero, and the icon is
      // embedded at compile time — so the value is refused here instead.
      if (arg === '--threshold' && value >= FULL_ALPHA) {
        die(`--threshold must be below ${FULL_ALPHA}`);
      }
      if (arg === '--size' && !Number.isInteger(value)) die('--size needs an integer');
      options[arg.slice(2)] = value;
    } else if (arg === '-h' || arg === '--help') {
      process.stdout.write(
        'usage: node scripts/gen-tray-icon.mjs [--size 128] [--threshold 85]\n',
      );
      process.exit(0);
    } else {
      die(`unknown option '${arg}'`);
    }
  }
  return options;
}

const options = parseArguments();
const master = decodePng(readFileSync(MASTER));
process.stdout.write(`  master   ${MASTER} (${master.width}x${master.height})\n`);

// The extraction runs at 256 px: a neon stroke is a pixel or two wide at this
// size, and at 1258 px the same stroke is a wide band whose glow would drag
// the threshold around.
const work = 256;
let pixels = downscale(master.pixels, master.width, master.height, work, work);
pixels = extractMark(pixels, options.threshold);
pixels = downscale(pixels, work, work, options.size, options.size);

writeFileSync(OUTPUT, encodePng(options.size, options.size, pixels));
process.stdout.write(
  `  wrote    ${OUTPUT} (${options.size}x${options.size}, threshold ${options.threshold})\n`,
);
