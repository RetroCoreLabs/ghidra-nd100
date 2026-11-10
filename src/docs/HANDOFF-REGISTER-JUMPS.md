# Handoff: jumps through a register (2026-11-10)

## Where things stand

- `main` is 14 commits ahead of `origin/main`. Not pushed: Ronny has not said push. The
  `nd100-definitions` submodule has 1 unpushed commit too.
- Last code commit: f5d9298 "Register operations read P as the next word; follow table jumps
  through a register". Language version 1.2.
- That build is installed in Ronny's Ghidra 12.2 (user Extensions folder) and checked by hash.
- `ND-100/data/manuals/nd100_manual.pdf` shows as modified. It is not from this work; leave it.

## What was done

1. The spec sets `P = p_next;` at the start of every register operation that can write P
   (see `src/docs/HOW-THE-SPEC-IS-BUILT.md`, fix 5).
2. `ND100ReturnTracker.java`: `tableJump()` runs a register-operation jump once per value of
   an index register with at most 4 unknown bits, and records the targets in `computedJumps`
   (only jumps of the routine itself, never a return from an inlined call).
3. `ND100CallReturnAnalyzer.java`: `followComputedJumps()` adds the references and disassembles
   the targets, and repeats while new calls appear.
4. Measured on all six test programs; results table in `src/PLAN.md`. No program lost a function.

## Where to start next

Read `src/PLAN.md`, section "Open". The SIMDEBUG-O items are the direct follow-up:

- 46 calls stop at the 20000-step limit (`STEP_BUDGET`, `ND100ReturnTracker.java`). Steps are
  visits, not distinct instructions. Measure both for 0x14a5 -> 0x1509 before changing it.
  Ronny suggested 65536; capping distinct instructions at 65536 is sound, total visits need a
  measured figure.
- 27 calls stop at "no instruction at 0xaa40" via the table entry at 0x1a55, `JMP I *0x1a57`.
- A table index read from the program file gives only one target (0x1a62).
- Register field 0 reads STS in the spec, 0 in nd100x. Check which instructions use field 0
  before changing it; raise the language version when you do.

## Rules that apply here

- Install into Ghidra only when Ronny has closed it.
- Measure all six programs before and after any change.
- Ask before pushing; check `git remote -v` first.
