# Plan

**Next:** CHAT.PROG still has 43 calls the tracker cannot place and 712 instructions outside
any function; list them one by one. FLOPPY-FU's runtime is still not decoded (0 placed).

## Measured 2026-11-08 (headless, every function decompiled)

| | Tracker off (2026-11-07) | Tracker on |
|---|---|---|
| ASSEMBLER-500: functions / failing | 22 / 1 (word 0 timed out) | 46 / 0 |
| ASSEMBLER-500: instructions outside any function | 462 | 287 |
| ASSEMBLER-500: calls with a tracker note / left | - | 106 / 2 |
| CHAT.PROG: functions / failing | 169 / 0 | 224 / 0 |
| CHAT.PROG: instructions outside any function | 3570 | 712 |
| CHAT.PROG: calls with a tracker note / left | - | 1450 / 43 |
| FLOPPY-FU-1986F: functions / calls placed / left | - | 9 / 0 / 18 |

What got ASSEMBLER-500's word 0 to decompile (2026-11-08):
- assumption 8: a path into a word the same summary loaded as a constant is dropped (the
  counter-wrap path at octal 015301/015324 into the table at 0x1ad6);
- assumption 9 (Ronny's choice): a call through a handler table in this runtime returns to
  call+1 or call+2 (0x1ba9);
- recursion is worked out in rounds until the answer settles, instead of marking the result
  "unsure" (the entry routine's overflow path re-enters the entry routine);
- a call that never returns gets Ghidra's "call then return" flow override, so the decompiler
  stops there too; function bodies are re-checked after a change;
- a function is created at every call target the tracker worked out (Ghidra makes none behind
  a pointer word), and calls in code the analyzer disassembles itself are fed back to it.

## Open

- **CHAT.PROG: 43 calls not placed, 712 instructions outside functions.** Not listed one by
  one yet. Part may be PLANC's error word after each call (5ERET lands there; nothing in
  Ghidra's flow does). A flow reference from the call to that word was tried 2026-11-07 and
  made Ghidra split functions (169 -> 147), so it was removed.
- **ASSEMBLER-500: 2 calls not placed:** 0x1ba9 and 0x1c02, calls through a pointer whose own
  return cannot be placed (the runtime rule covers the routine that makes them, not the call
  itself). 287 instructions outside functions, not listed yet.
- **CHAT.PROG "no instruction at 0xd111":** a path runs to the last word of bank 1.
- **FLOPPY-FU:** its runtime is neither PLANC nor ASSEMBLER-500's. Not decoded yet.
- **PLANC frame units:** the manual's heading says "in bytes"; CHAT.PROG's 5ENTR (0xd096)
  uses `,B -176` / `,B -177` / `,B -200` directly, which supports words.
- **Assumption 8 was chosen by measurement, not by Ronny.** Two wider versions were rejected
  ("words any instruction reads" cost CHAT about 200 placed calls and 11 functions).
