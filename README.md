# ghidra-nd100

[![build](https://github.com/RetroCoreLabs/ghidra-nd100/actions/workflows/ci.yml/badge.svg)](https://github.com/RetroCoreLabs/ghidra-nd100/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/RetroCoreLabs/ghidra-nd100)](https://github.com/RetroCoreLabs/ghidra-nd100/releases)
[![licence](https://img.shields.io/github/license/RetroCoreLabs/ghidra-nd100)](LICENSE)
[![downloads](https://img.shields.io/github/downloads/RetroCoreLabs/ghidra-nd100/total)](https://github.com/RetroCoreLabs/ghidra-nd100/releases)

**ghidra-nd100 is a plugin for the Ghidra reverse-engineering tool that lets it read, disassemble and annotate programs written for Norsk Data's ND-100 minicomputer.**

[What it does](#features) · [Install](#installation-in-ghidra) · [Building](#building-from-source) · [About the ND-100](#about-the-nd-100)

<!-- A 5-15 second recording of an ND-100 program being imported and disassembled in Ghidra. Under 10 MB.
![Ghidra showing an ND-100 program imported with this plugin: the disassembly listing with named routines and comments.](docs/images/readme/demo.gif)
-->

**Latest build:** https://github.com/RetroCoreLabs/ghidra-nd100/releases/latest

Ghidra processor module for the **ND-100** architecture: Sleigh specification, disassembly, and analysis support. This repository builds the installable **ND-100** extension (ZIP) for Ghidra.

## NDGen is legacy; this repo is the future

**NDGen** was the old **monolithic** repo that held multiple generators in one tree. That model is **being retired**—we are **migrating each tool into its own GitHub repository**.

**This repository** is the **standalone home** for the Ghidra ND-100 processor module: clone **this** repo, pull **`nd100-definitions`**, run **`build.bat`**. **You do not need the NDGen repository** to build or ship the extension.

Some C# namespaces or paths still say `NDGen.*` from the extracted generator code—that is **legacy naming**, not a dependency on the NDGen repo.

## Repository layout

```
build.bat                          Main build script (Windows)
ND100.Ghidra.sln                   C# solution (code generator)
src/                               C# generator source
  ND100.Ghidra.Tool/               Entry point for code generation
  NDGen.Generators.Common/         Shared generator base classes
  NDGen.Generators.Ghidra/         Ghidra-specific generators + Java/Sleigh templates
    Ghidra/ND-100/                 Template source for the extension
nd100-definitions/                 Git submodule — YAML CPU spec (instruction definitions)
ND-100/                            Generated extension project (populated by build.bat)
  data/languages/                  Generated Sleigh files (.slaspec, .sinc, .sla, ...)
  src/main/java/nd/bpun/           Java analyzers and loaders
  data/manuals/                    ND-100 manual PDF and index
  dist/                            Output ZIP produced by Gradle
.github/workflows/ci.yml           CI: build on every push to main
.github/workflows/release.yml      CI: build + publish release on version tag
```

Every path above is relative to the repository root (the directory containing `.git`).

## Features

- Sleigh specification for the ND-100 instruction set
- Disassembly and instruction decoding
- Operand handling for defined addressing modes
- File format loaders:
  - **BPUN** (Bootable Punched Tape), including the FloMon variant
  - **PROG** (SINTRAN III executable), 1-bank and 2-bank (bank 2 as overlay)
  - **BRF** (Binary Relocatable Format, ND-60.066.04) — emulates the ND
    Relocating Loader: relocation, fix-ups, ENTR/REF symbol linking, COMMON
    blocks, per-unit checksum verification; annotates the listing with file,
    unit, and symbol metadata comments
- Java analyzers: TPE test loader, IO/MON call analysis, stack frame analysis
- Initial analysis support (control flow, references)

## Status

Version 0.4.1 (tag `v0.4.1`, 16 November 2026), built for Ghidra 12.2.

- **Disassembly:** Instruction coverage is driven by shared YAML definitions; validate against your own binaries.
- **Semantics:** P-code and behavior for some instructions are still incomplete.
- **Decompiler:** Not available as a reliable, architecture-accurate output for ND-100 in this module.

## Scope

**Supported today**

- Core ND-100 instruction set (as defined in the linked specification sources)
- Basic addressing modes covered by the Sleigh spec
- Linear disassembly in Ghidra

**Not supported**

- Full MMU modeling
- Complete microcode-level semantics for all instructions
- Accurate decompiler output (do not expect C-like decompilation to match hardware)

## Architecture overview

The ND-100 is a **16-bit minicomputer** architecture with:

- **Fixed 16-bit** instruction width
- **Several instruction classes** with **irregular** bit layouts (not a single uniform decode table)
- **Memory-mapped I/O**
- **Optional MMU** with paging in some system configurations (not fully modeled in this module; see *Scope*)

## Generation

The Sleigh input (`.slaspec` and related artifacts under `ND-100/data/languages/`) is **generated** from a **YAML-based** instruction definition ([nd100-definitions](https://github.com/RetroCoreLabs/nd100-definitions)), not maintained by hand in this tree.

**Pipeline:**

```
YAML (nd100-definitions/specs/cpu.yaml)
  → C# generator (ND100.Ghidra.Tool)
  → .slaspec / .sinc / .pspec / .cspec files  +  Java source
  → Gradle buildExtension
  → ghidra_*_ND-100.zip  (installable Ghidra extension)
```

**Do not edit generated Sleigh or generated language files manually** — change the **YAML** or the **generator**, then regenerate.

## Prerequisites

| Tool | Notes |
|------|-------|
| **Git** | Needed to fetch the `nd100-definitions` submodule |
| **.NET 10 SDK** | Runs the C# code generator (the projects target `net10.0`) |
| **Java 25 (JDK)** | Required by Ghidra 12.2 and Gradle 9.1. Set `JAVA_HOME` to it (see below) |
| **Ghidra 12.2** | Set `GHIDRA_INSTALL_DIR` to the installation root (see below) |

Gradle itself does **not** need to be installed: the Gradle wrapper (`gradlew.bat`) downloads Gradle 9.1.0 on the first build. Gradle older than 9.1 cannot run on Java 25.

## Environment variables

Two variables must be set before building.

| Variable | Points at | Used by |
|----------|-----------|---------|
| `GHIDRA_INSTALL_DIR` | The root of the Ghidra installation, e.g. `C:\path\to\ghidra_12.2_PUBLIC` | `build.gradle` loads Ghidra's `support/buildExtension.gradle` from here, so the extension is built against this Ghidra version |
| `JAVA_HOME` | The root of a **JDK 25** installation (not a JRE, and not the `bin` folder) | The Gradle wrapper runs Gradle and the Java compiler from here |

```bat
set GHIDRA_INSTALL_DIR=C:\path\to\ghidra_12.2_PUBLIC
set JAVA_HOME=C:\path\to\jdk-25
```

To make them permanent on Windows, set them as user environment variables (System Properties → Environment Variables) and open a **new** terminal; an already open terminal keeps the old values.

`build.bat` fails immediately with a clear error if `GHIDRA_INSTALL_DIR` is not set. There is no default or auto-discovery fallback. If `JAVA_HOME` points at an older Java (for example 21), the Java compile step fails: Ghidra 12.2's `buildExtension.gradle` sets the Java source level to 25, which an older JDK cannot compile.

The extension zip only installs into the Ghidra version it was built against, so `GHIDRA_INSTALL_DIR` decides which Ghidra the result is for.

## Building from source

**Clone (including submodule)**

```bat
git clone https://github.com/RetroCoreLabs/ghidra-nd100.git
cd ghidra-nd100
git submodule update --init --recursive
```

**Full build** (codegen → Gradle → ZIP)

```bat
set GHIDRA_INSTALL_DIR=C:\path\to\ghidra_12.2_PUBLIC
build.bat
```

The extension ZIP is written to `ND-100\dist\ghidra_*_ND-100.zip`.

**Gradle only** (skip C# codegen, use existing generated files)

```bat
build.bat gradle-only
```

**Regenerate Sleigh only** (no Gradle)

```bat
dotnet build ND100.Ghidra.sln -c Release
dotnet run --project src/ND100.Ghidra.Tool -c Release --no-build
```

## Installation in Ghidra

1. Build or download the extension ZIP from the [Releases](../../releases) page.
2. In Ghidra: **File → Install Extensions… → Add (+)** and select the ZIP.
3. Restart Ghidra when prompted.

## Releases (CI / GitHub Actions)

Pushing a version tag triggers `.github/workflows/release.yml`, which:

1. Checks out the repo with submodules
2. Downloads and caches the Ghidra distribution
3. Runs `build.bat` (full codegen + Gradle)
4. Renames the output zip to `ghidra-nd100-<version>.zip`
5. Publishes it as a GitHub Release asset

**Versioning**

| Version | Milestone |
|---------|-----------|
| 0.1.x   | Initial instruction decoding |
| 0.5.x   | Stable disassembly |
| 1.0.0   | Full semantics |

The version is embedded in the extension (`extension.properties`) and in the release zip name (`ghidra-nd100-<version>.zip`). `MODULE_VERSION` defaults to `0.1.0` when building locally without a tag.

**To release a new version:**

```bat
git tag v0.1.0
git push origin v0.1.0
```

One variable at the top of `release.yml` controls the Ghidra version:

```yaml
env:
  GHIDRA_VERSION: '12.2'
```

The download URL is resolved automatically from the Ghidra GitHub Releases API — no build date to track. Update `GHIDRA_VERSION` when upgrading Ghidra.

## Submodule: nd100-definitions

The `nd100-definitions/` directory is a Git submodule pointing to:

```
https://github.com/RetroCoreLabs/nd100-definitions.git
```

`build.bat` initialises it automatically if `nd100-definitions/specs/cpu.yaml` is missing. To initialise manually:

```bat
git submodule update --init --recursive
```

## About the ND-100

The ND-100 was a 16-bit minicomputer made by Norsk Data, a Norwegian computer company, in the
1980s. Most of them ran Norsk Data's own operating system, SINTRAN III. Its programs come as punched-tape images (BPUN), SINTRAN program files (PROG)
and relocatable object files (BRF). The machines are long gone from service, so reading their
software today means a disassembler that knows the instruction set and those file formats - which
is what this plugin adds to Ghidra. More on the company: [Norsk Data on Wikipedia](https://en.wikipedia.org/wiki/Norsk_Data).

## References

- **[nd100-definitions](https://github.com/RetroCoreLabs/nd100-definitions)** — YAML / JSON instruction set and CPU metadata used by the generator
- **ND-100 architecture documentation** — see generated manual assets and project docs shipped with the extension where applicable
- **Emulator / tooling** — cross-check disassembly against execution-level models when validating; this module does not bundle an emulator

## Rights

- **No Norsk Data software ships in this repository.** One program binary, `MAC.BPUN`, was removed
  from the current tree on 2026-10-18; it is still in older commits.
- **`ND-100/data/manuals/nd100_manual.pdf` is generated** by this project's own manual generator
  from the instruction definitions. It is not a scan of a Norsk Data manual.
- Norsk Data no longer operates, and I do not know who holds the rights to its software and
  manuals today. If you hold them and want something removed, open an issue in this repository.

## Examples

The **`examples/`** directory is reserved for **small, rights-cleared ND-100 binaries** used to regression-test disassembly and analysis. None are required for the build.

## Contributing

See [CONTRIBUTING.md](.github/CONTRIBUTING.md). Security problems go through
[SECURITY.md](.github/SECURITY.md), never a public issue.

## Licence

MIT. See [LICENSE](LICENSE).
