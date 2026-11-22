# Plan

**Next:** list the words outside functions; then decode error slots the compiler wrote even
when the called routine never error-returns (see Open, TPE-MON 0x2f3c).

## Measured 2026-11-09 (headless, four programs, tracker off vs on)

| Program | Functions off -> on | Outside any function off -> on | Functions lost |
|---|---|---|---|
| TPE-MON-100-B00.BPUN | 143 -> 201 | 390 -> 3706 | 1 (0x2f3c, see Open) |
| CHAT.PROG | 183 -> 242 | 3001 -> 3978 | 0 (see below) |
| ASSEMBLER-500.PROG | 22 -> 46 (word 0 now decompiles) | 462 -> 287 | 0 |
| FLOPPY-FU-1986F.BPUN | 2 -> 9 | 287 -> 173 | 0 |

"Outside" counts instructions. Every function decompiles in all four. CHAT's 0xa55e is no
longer a function start: with the tracker off it was one only because the plain `JMP 0xa55e`
at 0xa51a carried a call flag; it is now inside the routine at 0xa546, as it should be.
The earlier CHAT figure of 712 outside came from a run that crashed partway (fixed since: the
call is fetched again after the listing is cleared).

## Jumps through a register (2026-11-09)

Register operations now set P to the next word before they run (nd100x `regop()`: the
instruction's own address is `gPC - 1`; ND-06.014.2A page 158). Before, a read of P read a
register no analysis can know, so `RADD SA DP` / `RADD SD DP` table jumps were unknown. The
tracker follows such a jump when its index register has at most 4 unknown bits, by running the
instruction once per value, and hands the targets to the listing (only jumps of the routine
itself, never a return from a call it followed). Language version 1.2.

| Program | Functions | Instructions | Outside any function | Lost |
|---|---|---|---|---|
| TPE-MON-100-B00.BPUN | 199 -> 199 | 13476 -> 13476 | 3607 -> 3607 | 0 |
| CHAT.PROG | 245 -> 245 | 18107 -> 18107 | 3877 -> 3877 | 0 |
| ASSEMBLER-500.PROG | 46 -> 46 | 1682 -> 1682 | 287 -> 287 | 0 |
| FLOPPY-FU-1986F.BPUN | 9 -> 9 | 289 -> 402 | 173 -> 286 | 0 (two 8-entry JMP tables, 0x09b2, 0x09fb) |
| SIMDEBUG-O.PROG | 34 -> 39 | 1251 -> 1389 | 95 -> 178 | 0 (4-entry table at 0x1a53) |
| SIMULA.BPUN | 25 -> 25 | 805 -> 805 | 137 -> 137 | 0 |

## PLANC marks (automatic, 2026-11-08)

When analysis ends, `ND100PlancMarks` names the PLANC runtime from what its code does (5ENTR,
5INIT, 5LEAV, 5ERET), marks the inline words after the entry call and comments the error slot
after each call to a PLANC routine. Every comment carries `[nd100-planc]`; a person's name or
comment is never replaced. Measured: TPE-MON and CHAT.PROG get exactly 5ENTR / 5LEAV / 5ERET
(TPE-MON 0x6650 / 0x666a / 0x6664, CHAT 0xd096 / 0xd0b3 / 0xd0ad, checked by reading the code);
ASSEMBLER-500 and FLOPPY-FU get nothing. Error slots commented: TPE-MON 75, CHAT 41; inline
words: CHAT 147, TPE-MON 116.

Still to do from the MC68000 PLANC scripts (NDInsight tools/ghidra-planc): an ON ROUTINEERROR
comment (CHAT 0x76b4: `COPY SL DX; STX ,B; STA ERRCODE; LEAVE; JMP I ,B`), a plate per PLANC
routine with its frame size, function tags, and a PLANC calling convention for the decompiler.

## Open

- **X25PF decompiles to `halt_baddata()` (X25-LINK-C00.BRF 0x18a9).** After `MON 0x5c`
  (ExitRTProgram, never comes back) the flow runs on into `BORA` and the data word at 0x18af,
  so the decompiler warns "Bad instruction". Same family as MON 0 above: a MON that ends the
  program must end the flow. Shows in the README demo's last frame.

- **MON 0 does not end the flow (CHAT.PROG 0xd110).** MON 0 (ExitFromProgram) never comes
  back, but the language lets the flow go on, so Ghidra tries to decode 0xd111 and marks it
  Bad Instruction.
- **Remaining Bad Instruction marks in CHAT.PROG (13 after the 2026-11-21 fix; was 147).**
  At 0x150a, 0x4c8c, 0xc325 and others an ordinary instruction is followed by a pointer word
  (to 5ERET): the "instruction" is most likely data decoded as code. Find what sends the
  flow there.
- **Repeated comment `B+26  B+26  B+26` (CHAT.PROG 0x4c8c).** An analyzer (likely the Stack
  Frame Annotator) appends its comment again on every analysis run.

- **The generator writes a stale `ND-100/extension.properties`.** Seen 2026-11-18: running
  `src/ND100.Ghidra.Tool` replaced the committed file (name "ND-100 Processor Module", description
  naming the BPUN, PROG and BRF loaders, version 0.1.0) with an older text (name "ND-100", "BPUN file
  format loader" only, version 12.2, a date in createdOn). The committed file was restored by hand.
  The fix is in the generator's template for this file, so a build gives the right text by itself.
- **BRF loader: a broken reference chain is logged and the walk stops; the real linker keeps
  walking.** Measured 2026-11-16 on BRF-LINKER C01 (nd100x, fresh boot per file, hand-made units):
  REF TSTX at word 1, then AFR 5 onto it, then TSTX defined at 3. Result: word 1 = 3 (the +5 is
  lost), and 3 was also written at address 4 (the changed link), at 0 (over the program's own first
  word 111111) and at 111111; no message. With two REFs and the add on the first: words 0, 1, 2 and
  address 111111 all = TSTX. Symbol defined first, then REF + AFR 5: word = TSTX + 5 (the loader
  does this). So the chain lives in memory as the manual says, and adding onto a reference to a
  symbol not yet defined is not supported. TCP-ERROR-1-B05 does it for 5UTBY and 5STCO (PLANC runtime
  routines, normally defined by an earlier library in a real load). Open: the exact rule that ends
  the real walk (these numbers do not fix it), so the loader does not copy its stray writes.
- **BRF loader, two-bank: 4 fix-ups still land on REF words** with separate program/data
  counters (1720 of 1724 land cleanly; with one shared counter, 48 hit never-loaded words and 65
  hit REF words): NK-100-2BANK-C03 file offset 0x1b10 (AFR 26 onto REF 5ERET), SLIB-NRE-2B-B01
  0x9a94, 0xe236, 0x10180. Probably the same question as the item above; in the one-bank build of
  NK the matching fix-up lands on REF AIL0 instead, so the two-bank placement may also be off.
- **BRF loader, two-bank: the data bank's first address is not in the file.** It is set at load
  time; the loader puts it at 0 in overlay space BRF_DATA and says so in the file header comment.
  Also unknown from the files: whether LR in data mode uses the data base or the program base (no
  LR occurs in data mode in the 13 two-bank files), and two-bank COMMON (ASF upward in the data
  bank, section 2.6) - no ASF in any of the 48 files. AFF and ARF (fix-up types 4 and 5) occur in
  none of the 48 files either.
- **BRF loader loads every library unit;** the real loader loads one only when a symbol of it is
  referenced (LIBR, section 2.4; RT-LOADER LOAD/X-LOAD). Units past 64K words go to overlay spaces
  BRF_PAGE2, BRF_PAGE3 (X25-UTILITY-C00 from unit 548, TCP-ERROR-1-B05 from units 65 and 235). A
  library that defines a symbol twice (X25-UTILITY: 5ERROR in two units) shows both; the real
  loader would skip the second unit.
- **SIMDEBUG-O.PROG is still mostly undecoded** (1389 instructions in 30062 words). What stops
  it, from the tracker log: 46 calls over the 20000-step limit; 27 calls stopped at "no
  instruction at 0xaa40" - entry 1 of the table at 0x1a53 is `JMP I *0x1a57`, which takes the
  instruction word at 0x1a57 as a pointer and lands outside the program. Not known whether that
  index value never happens or something else is misread there.
- **A table index read from the program file gives one target only.** SIMDEBUG-O 0x1a62:
  `SAA 3; AND 4,X; RADD SA DP` - the word at X+4 comes from the file, so the tracker sees one
  value and follows only 0x1a65 of the four entries. A test on such a word already goes both
  ways (assumption 1b); a table jump on it does not yet.
- **Register field 0 reads STS in the spec, 0 on the machine.** `attach variables [ rop_dst
  rop_src ... ] [ STS D P B L A T X ]` makes source field 0 the status register; nd100x
  `regop()` reads it as 0 ("oracle-validated against the RASK microcode"). Not changed yet:
  which instructions decode with field 0 and what each must do has to be checked first.

- **Error slots behind routines that never error-return are not decoded.** Since each routine
  records the fixed words it writes (2026-11-09), TPE-MON's 5ENTR is worked out and its 116
  stack-size words are marked, but the tracker now also knows exactly which routines can
  ERRETURN. TPE-MON 0x5fe7 (one MON 0x63, then 5LEAV) never does, so the word after its call at
  0x2f9b, `JPL 0x2f3c` (an ON ROUTINEERROR handler), is never reached and 0x2f3c is no longer a
  function; error-slot comments went 97 -> 75 the same way. The compiler still wrote those
  words as code, so they could be decoded as such without being reached.

- **Many more instructions outside functions with the tracker on** (TPE-MON 390 -> 4286).
  Not listed yet. Part is code the tracker newly disassembled (error slots, code behind
  pointer words) that no function owns; CHAT 0xa518-0xa51a is one such run.
- **Unresolved indirect jumps:** TPE-MON 78, CHAT 70, ASSEMBLER-500 50. Shapes in TPE-MON:
  `JMP I -0x71,B` (a jump through a frame word), `JPL 0,X` (a routine pointer), `JMP 1,X`
  (an indexed table).
- **ASSEMBLER-500: 0x1ba9 and 0x1c02,** calls through a pointer whose own return cannot be
  placed.
- **CHAT.PROG "no instruction at 0xd111":** a path runs to the last word of bank 1.
- **FLOPPY-FU:** its runtime is neither PLANC nor ASSEMBLER-500's. Ronny: probably written in
  plain assembler, so look for hand-written shapes, not a compiler runtime. Not decoded yet.
- **Assumption 8 was chosen by measurement, not by Ronny.** Two wider versions were rejected
  ("words any instruction reads" cost CHAT about 200 placed calls and 11 functions).
- **Assumption 1b (2026-11-08) was chosen from one measured case** (TPE-MON's flag word
  0x6a0e): a test on a word read from the program file goes both ways, except in start code.
