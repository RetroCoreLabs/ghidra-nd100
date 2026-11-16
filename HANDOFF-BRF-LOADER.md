# Handoff: BRF Loader for the ND-100 Ghidra Extension

First written 2026-07-08; rewritten 2026-11-16 to match the loader as it is now.
Scope: ND-100 **BRF (Binary Relocatable Format)** import, beside the BPUN and :PROG loaders.

The format itself is described in `SINTRAN/File-Formats/BRF-FILE-FORMAT.md` in the NDInsight
repository; that document carries the measurements behind every rule below. Open questions
are in `src/PLAN.md` here.

---

## Where it is

- Source of truth: `src/NDGen.Generators.Ghidra/Ghidra/ND-100/src/main/java/nd/bpun/BRFLoader.java`.
  Copy it to `ND-100/src/main/java/nd/bpun/BRFLoader.java` (the generated tree) after every
  change; the generator overwrites `ND-100/`.
- Primary manual: `Reference-Manuals/ND-60.066.04 ND Relocating Loader.md` in NDInsight.

## What the loader does

It loads the file the way the ND Relocating Loader / BRF-LINKER does (ND-60.066.04 chapter 2):

- Reads the groups; P-groups are big-endian 16-bit words; every control number 0-054 is read.
- **Checksum**: the whole unit including the stored word sums to 0 (two's complement). Checked
  on all 2472 units of the 48 BRF files in NDInsight. The file-type check reads the whole
  first unit (up to 4 MB) and its checksum.
- **Six-bit names**: each character is the LOW SIX BITS of its ASCII code. 01-037 are `A`-`Z`
  and `[\]^_` (ASCII 0100 + code), 040-077 are the ASCII characters themselves, 0 is a space.
  Code 0 pads on the left and on the right (PLANC internal labels). 5 characters in a 4-byte
  S-group, 7 in a 6-byte one (after LONGF, which is per unit). The first version used
  "ASCII - 040", which garbled every name.
- **PB = CLC at BEG minus 1.** Measured on BRF-LINKER and over 4701 fix-ups.
- **REF takes one word** and follows the reference chain of section 2.5: a defined symbol's
  value is stored at once; an undefined one gets a link to its previous reference (177777 for
  the first) and the chain is patched when ENTR defines the symbol. A fix-up onto a REF word
  works when the symbol is already defined ("AIL0 + 026" in NK-100-1BANK-C03). When the
  symbol is NOT yet defined, the fix-up changes a link: BRF-LINKER C01 then follows it without
  a message and writes the address into wrong places (measured 2026-11-16). This loader stops
  the walk there and logs "Reference chain of X is broken" (TCP-ERROR-1-B05: 5UTBY, 5STCO).
- **Two-bank files** (PMO/DMO/LRP/LRD): one load counter and one base per bank; the data
  bank goes to overlay space `BRF_DATA` starting at 0 (its real start is set at load time).
- **MAIN** marks the start address: label, entry point, disassembly start. It is not entered
  as a symbol a REF can link to: in an RT load the MAIN name stands for the RT description.
- **Library units are all loaded** (the real loader loads only referenced ones). A unit that
  would pass 0177777 starts in a new overlay space `BRF_PAGE2`, `BRF_PAGE3`, ...
- REF to a symbol not defined in the file becomes a Ghidra import (external reference); every
  REF word gets a relocation entry.
- COMMON (one-bank) is allocated downward from 0177777 (section 2.6).
- Comments: a file header plate at the entry, a plate per unit (offset, PB, size, checksum,
  RT priority, symbols, ctrl-30 identification text), an EOL comment on every REF word, a
  pre-comment on every definition. Comments are appended, never overwritten.

## How to build, install and test

- From PowerShell in `ND-100`: set `$env:GHIDRA_INSTALL_DIR` to the Ghidra 12.2 folder, then
  `.\gradlew.bat --no-daemon buildExtension`.
- Install: copy `ND-100\build\libs\ND-100.jar` to
  `%APPDATA%\ghidra\ghidra_12.2_PUBLIC\Extensions\ND-100\lib\`. Ghidra must be closed: a running
  Ghidra holds that file. Ghidra only reads the extension at start.
- Headless test into a scratch project (never Ronny's project, which is locked while Ghidra runs):
  `analyzeHeadless.bat <scratch>\hp t -import <file> -noanalysis -overwrite`
  (`-import` takes one file; `-folderPath` does not exist in 12.2). Check the log for "Import
  succeeded" and for "broken", "redefined" and "checksum".
- 2026-11-16: all 48 BRF files in NDInsight import. Expected messages: the two broken chains in
  TCP-ERROR-1-B05, and "Symbol X redefined" in library files that define a name in two units
  (X25-UTILITY-C00, X25-LTST-C00, TCP-ERROR-1-B05, SLIB-REE-*).

## Design notes

- Same package (`nd.bpun`) and style as `BPUNLoader`/`ProgLoader`; language
  `ND-100:BE:16:default`, word-addressed (`addressableUnitSize == 2`).
- Overlay blocks are made with `createInitializedBlock(..., overlay=true)`, one per extra space;
  `createOverlaySpace` followed by normal blocks fails with "Part of range already exists".
- The same rules are in NDInsight `scripts/nd100_brf.py` (`materialize_memory()`), which gives
  the same broken chains on the same 48 files.
