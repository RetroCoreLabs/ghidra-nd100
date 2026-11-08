# How the ND-100 SLEIGH spec is built

Read this before changing anything under `ND-100/data/languages/`. It records where the
spec comes from, what was checked, and the traps found while fixing it.

## Short version

`ND-100/data/languages/nd100.slaspec` is **generated. Never edit it by hand.** A full
build (`build.bat`) overwrites it.

It is made from two inputs, joined by a C# generator:

| Part | What it decides | Where it lives | Written by |
|---|---|---|---|
| Decoding | which bits make which instruction, operand fields, mnemonics | `nd100-definitions/specs/` (YAML, a git submodule) | metadata taken from the ND-100 manual |
| Semantics | what each instruction does (the p-code) | `src/NDGen.Generators.Ghidra/Ghidra/Templates/p-codes/*.sinc`, one file per instruction | by hand |
| Shared base | registers, spaces, operand sub-tables | `src/NDGen.Generators.Ghidra/Ghidra/Templates/nd100-base.slaspec` | by hand |
| Glue | builds the constructor header from the YAML and pastes in the `.sinc` body | `src/NDGen.Generators.Ghidra/Ghidra/GhidraSleighGenerator.cs` | C# |

The generator copies the hand-written p-code **unchanged**. Running it on an unchanged tree
gives back the committed `nd100.slaspec` with no differences (checked 2026-11-07), so the
generated file and the hand-written sources cannot drift apart.

Most `.sinc` files hold only a body. A few hold **whole constructors** (header included)
because their operand forms do not fit one generated header: `JPL`, `JMP`, `SWAP`, `RADD` and
a handful more. For those, the header in the `.sinc` file is the one that counts.

## Where to make a change

- Wrong mnemonic, wrong bits, wrong operand field: fix the YAML in `nd100-definitions`.
- Wrong behaviour of one instruction: fix its `.sinc` in `Templates/p-codes/`.
- A rule that applies to many instructions (shared operand tables, P-jumps): `nd100-base.slaspec`
  plus, if the header must change, `GhidraSleighGenerator.cs`.
- Then run `build.bat` (generate + Gradle). `build.bat gradle-only` skips the generator.
- The generator also rewrites `ND-100/extension.properties` from the shell's
  `GHIDRA_INSTALL_DIR`. If that variable points at an old Ghidra, the version in that file
  goes wrong. Check it before committing.

`src/NDGen.Generators.Ghidra/Ghidra/ND-100/data/languages/nd100.slaspec` is an **old,
dead copy** (153 constructors, March 2026). `build.bat` never copies it. Do not edit it and do
not read it as the current spec.

## History

The spec was first built in the separate NDGen repository and then moved here:

- 2026-03-08 NDGen: p-code written for all 151 instructions.
- NDGen: JMP/JPL constructors moved from C# into static `.sinc` files; skip and shift decoding fixed.
- 2026-03-09 NDGen: every instruction's p-code was compared against the YAML and against the
  nd100x emulator (`cpu_instr.c`), a working emulator. More than 40 bugs were fixed (ENTR/LEAVE
  frame offsets, RADD variants, bit-op K flag, carry convention of SUB, shifts, and others).
- 2026-04-05 this repository: first commit.

## Fixes made 2026-11-06/07, and what they teach

Found while tracking where calls return in `ASSEMBLER-500:PROG`:

1. **JPL stored a byte address in L.** In a SLEIGH semantic body `inst_start` is a BYTE
   offset (Ghidra word size is 2), but inside a `[ ]` disassembly action it is the WORD
   address. `L = inst_start + 1` gave `2*addr+1`. Fixed with the `link_ret` sub-table in
   `nd100-base.slaspec`, which computes the value in a disassembly action.
   **Rule: never use `inst_start` or `inst_next` directly in a p-code body on this CPU.**
2. **SWAP was a one-way copy.** It is an exchange of the two registers. Fixed in `SWAP.sinc`.
3. **An instruction that writes P did not jump.** Writing P (for example `COPY SL DP`, the
   EXIT instruction, or `RADD AD1 SL DP`) is a jump. The `rop_jmp` / `reg3_jmp` sub-tables add
   `goto [P]` when the destination field is P. The generator adds them only to instructions
   whose body writes their destination register (`rop_dst = ...` / `reg3 = ...`): COPY, RADD,
   RAND, REXO, RORA, RSUB, SWAP, RCLR, RINC, RDCR. EXR, RDIV, RMPY, LRB, SRB and MOVEW share the
   same header shape but write no register named by that field, so they do not get it.

The emulator comparison did not catch these three. The likely reason (not verified): an
emulator executes the instruction correctly, but these defects are about how the *Ghidra*
model expresses it (byte vs word addresses, flow to P), which an emulator never shows.

## Checks that exist today

- The SLEIGH compiler accepts the spec (part of the Gradle build).
- The extension installs and imports programs.
- `GhidraOutputValidator.cs` checks that output files exist and are well formed. It does not
  check decoding or behaviour.

There is no automatic test today that compares Ghidra's decoding with `nd100-dis`, or
Ghidra's p-code with what the emulator does.
