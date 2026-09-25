// gen-icons.swift — rebuild ui-desktop's macOS `icons/icon.icns` from the sharp master art.
//
// Why this exists: `src-tauri/icons/icon.icns` sits between a sharp master PNG and
// a blurry Dock icon. The shipped .icns was built from a tiny source (its 128 px and
// 1024 px representations are identical up to scaling — a pure upscale), while the
// PNG set next to it was rendered from the real master. Tauri copies the .icns into
// `nexa.app/Contents/Resources/icon.icns` verbatim, so whatever quality it has is
// what the Dock shows. Regenerating from the master is the whole fix.
//
// The master is `src-tauri/icons/nexapipe.png` (1258x1258), the only asset whose
// edge energy matches a genuine render at that size.
//
// Two shapes are supported:
//   macos       (default) — Apple's macOS icon grid: the art is scaled into the
//              824/1024 content box and clipped to a continuous-corner rounded
//              rect, so the icon reads as a normal macOS app icon instead of a
//              full-bleed square.
//   full-bleed  — the art fills the canvas edge to edge, square. Use this if you
//              deliberately want the legacy square look.
//
// Usage:
//   swift scripts/gen-icons.swift src-tauri/icons/nexapipe.png [--mode macos|full-bleed]
//                                                               [--pngs] [--keep-iconset]
// Run from `ui-desktop/`.

import CoreGraphics
import Foundation
import ImageIO
import SwiftUI
import UniformTypeIdentifiers

// MARK: - Constants

/// Fraction of the canvas occupied by the icon artwork, per Apple's macOS icon grid
/// (824 pt of content in a 1024 pt canvas).
let contentRatio: CGFloat = 824.0 / 1024.0

/// Corner radius as a fraction of the content box, per Apple's macOS icon grid
/// (185.4 pt on an 824 pt box). `RoundedRectangle(style: .continuous)` supplies the
/// superellipse-ish corner Apple actually uses, not a circular arc.
let cornerRatio: CGFloat = 185.4 / 824.0

/// Canonical canvas size for the largest .icns representation.
let masterSize = 1024

/// (pixel size, iconset file stem) — the ten representations `iconutil` expects.
let iconsetEntries: [(size: Int, stem: String)] = [
    (16, "icon_16x16"),
    (32, "icon_16x16@2x"),
    (32, "icon_32x32"),
    (64, "icon_32x32@2x"),
    (128, "icon_128x128"),
    (256, "icon_128x128@2x"),
    (256, "icon_256x256"),
    (512, "icon_256x256@2x"),
    (512, "icon_512x512"),
    (1024, "icon_512x512@2x"),
]

// MARK: - Small helpers

func die(_ message: String) -> Never {
    FileHandle.standardError.write(Data(("gen-icons: error: " + message + "\n").utf8))
    exit(1)
}

func note(_ message: String) {
    print("  " + message)
}

func step(_ message: String) {
    print("\n== " + message)
}

func sRGB() -> CGColorSpace {
    guard let space = CGColorSpace(name: CGColorSpace.sRGB) else { die("no sRGB color space") }
    return space
}

// MARK: - Arguments

enum Shape: String {
    case macos
    case fullBleed = "full-bleed"
}

struct Options {
    var source: URL
    var outputDir: URL
    var shape: Shape = .macos
    var emitTauriPngs = false
    var keepIconset = false
}

func parseArguments() -> Options {
    var positional: [String] = []
    var shape = Shape.macos
    var emitPngs = false
    var keepIconset = false

    var rest = Array(CommandLine.arguments.dropFirst())
    while !rest.isEmpty {
        let arg = rest.removeFirst()
        switch arg {
        case "--mode":
            guard !rest.isEmpty else { die("--mode needs a value") }
            let raw = rest.removeFirst()
            guard let parsed = Shape(rawValue: raw) else {
                die("unknown --mode '\(raw)' (expected macos or full-bleed)")
            }
            shape = parsed
        case "--pngs":
            emitPngs = true
        case "--keep-iconset":
            keepIconset = true
        case "-h", "--help":
            print("""
            usage: swift scripts/gen-icons.swift <master.png> [options]

              --mode macos|full-bleed   icon shape (default: macos)
              --pngs                    also refresh 32x32/128x128/128x128@2x from the master
              --keep-iconset            leave the intermediate .iconset directory in place

            Writes <master dir>/icon.icns next to the master.
            """)
            exit(0)
        case let unknown where unknown.hasPrefix("-"):
            die("unknown option '\(unknown)'")
        default:
            positional.append(arg)
        }
    }

    guard positional.count == 1 else {
        die("expected exactly one master PNG path, got \(positional.count). See --help.")
    }
    let source = URL(fileURLWithPath: positional[0]).standardizedFileURL
    guard FileManager.default.fileExists(atPath: source.path) else {
        die("master art not found: \(source.path)")
    }
    return Options(
        source: source,
        outputDir: source.deletingLastPathComponent(),
        shape: shape,
        emitTauriPngs: emitPngs,
        keepIconset: keepIconset
    )
}

// MARK: - Rasterising

func loadImage(_ url: URL) -> CGImage {
    guard let src = CGImageSourceCreateWithURL(url as CFURL, nil),
          let image = CGImageSourceCreateImageAtIndex(src, 0, nil)
    else {
        die("could not decode \(url.path) — expected a PNG")
    }
    return image
}

/// Renders `source` onto a square canvas of `size` px. In `.macos` mode the art is
/// scaled into the content box and clipped to the continuous-corner rounded rect;
/// in `.fullBleed` mode it fills the canvas.
///
/// Every size is rendered straight from the master rather than from a shrunken
/// intermediate, which keeps the small representations crisp.
func render(_ source: CGImage, size: Int, shape: Shape) -> CGImage {
    let canvas = CGFloat(size)
    let content = shape == .macos ? canvas * contentRatio : canvas
    let inset = (canvas - content) / 2

    guard let ctx = CGContext(
        data: nil,
        width: size,
        height: size,
        bitsPerComponent: 8,
        bytesPerRow: 0,
        space: sRGB(),
        bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
    ) else {
        die("could not create a \(size)x\(size) bitmap context")
    }
    ctx.interpolationQuality = .high
    ctx.setShouldAntialias(true)
    ctx.setAllowsAntialiasing(true)

    let box = CGRect(x: inset, y: inset, width: content, height: content)
    if shape == .macos {
        let squircle = RoundedRectangle(cornerRadius: content * cornerRatio, style: .continuous)
        ctx.addPath(squircle.path(in: box).cgPath)
        ctx.clip()
    }
    ctx.draw(source, in: box)

    guard let image = ctx.makeImage() else { die("could not rasterise \(size)x\(size)") }
    return image
}

func writePNG(_ image: CGImage, to url: URL) {
    guard let dest = CGImageDestinationCreateWithURL(
        url as CFURL, UTType.png.identifier as CFString, 1, nil
    ) else {
        die("could not create \(url.lastPathComponent)")
    }
    CGImageDestinationAddImage(dest, image, nil)
    guard CGImageDestinationFinalize(dest) else {
        die("could not write \(url.path)")
    }
}

func run(_ launchPath: String, _ arguments: [String]) {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: launchPath)
    process.arguments = arguments
    do {
        try process.run()
    } catch {
        die("could not run \(launchPath): \(error.localizedDescription)")
    }
    process.waitUntilExit()
    guard process.terminationStatus == 0 else {
        die("\(launchPath) failed with status \(process.terminationStatus)")
    }
}

// MARK: - Main

let options = parseArguments()
let fm = FileManager.default

step("Master art")
note("\(options.source.path)")
let master = loadImage(options.source)
guard master.width >= masterSize, master.height >= masterSize else {
    die("""
    master is \(master.width)x\(master.height); at least \
    \(masterSize)x\(masterSize) is required or the large .icns \
    representations will be upscaled (which is the bug this script fixes)
    """)
}
note("\(master.width)x\(master.height), shape: \(options.shape.rawValue)")

// The .iconset is a staging directory iconutil consumes; it is not an artefact.
let iconsetDir = options.outputDir.appendingPathComponent("icon.iconset")
try? fm.removeItem(at: iconsetDir)
do {
    try fm.createDirectory(at: iconsetDir, withIntermediateDirectories: true)
} catch {
    die("could not create \(iconsetDir.path): \(error.localizedDescription)")
}

step("Rendering \(iconsetEntries.count) .icns representations")
for entry in iconsetEntries {
    let file = iconsetDir.appendingPathComponent("\(entry.stem).png")
    writePNG(render(master, size: entry.size, shape: options.shape), to: file)
    note("\(entry.stem).png  \(entry.size)x\(entry.size)")
}

let icns = options.outputDir.appendingPathComponent("icon.icns")
step("Packing icon.icns")
run("/usr/bin/iconutil", ["-c", "icns", iconsetDir.path, "-o", icns.path])
let written = (try? fm.attributesOfItem(atPath: icns.path))?[.size] as? Int ?? 0
note("\(icns.path)  \(written / 1024) KiB")

if options.emitTauriPngs {
    step("Refreshing the Tauri PNG set")
    for (name, size) in [("32x32.png", 32), ("128x128.png", 128), ("128x128@2x.png", 256)] {
        writePNG(render(master, size: size, shape: options.shape), to: options.outputDir.appendingPathComponent(name))
        note(name)
    }
}

if !options.keepIconset {
    try? fm.removeItem(at: iconsetDir)
}

print("\nDone. Rebuild the app bundle, then refresh the Dock cache:")
print("  ./build_dmg.sh --bundles app        # or: npm run tauri:build")
print("  touch <path>/nexa.app && killall Dock")
