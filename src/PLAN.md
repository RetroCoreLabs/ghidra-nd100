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
- **FLOPPY-FU:** its runtime is neither PLANC nor ASSEMBLER-500's. Not decoded yet.
- **BFILL / MOVB error return on real hardware:** nd100x has none; not known for the real CPU.
- **PLANC frame units:** the manual's heading says "in bytes"; CHAT.PROG's 5ENTR (0xd096)
  uses `,B -176` / `,B -177` / `,B -200` directly, which supports words.
- **Assumption 8 was chosen by measurement, not by Ronny.** Two wider versions were rejected
  ("words any instruction reads" cost CHAT about 200 placed calls and 11 functions).
- **Assumption 1b (2026-11-08) was chosen from one measured case** (TPE-MON's flag word
  0x6a0e): a test on a word read from the program file goes both ways, except in start code.
