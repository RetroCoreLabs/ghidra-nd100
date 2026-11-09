/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nd.bpun;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.Msg;

/**
 * Works out where a call on the ND-100 really returns, by running the CALLED routine's own
 * code - its p-code, i.e. the SLEIGH semantics in nd100.slaspec - over abstract values.
 *
 * <p>Why this is needed: Ghidra assumes every JPL returns to the word right after it. On the
 * ND-100 that is often false, and which way it is false depends on the runtime the program
 * was built with:</p>
 * <ul>
 * <li>PLANC (ND-60.117.5 pages 291-294): the routine prologue is
 *     {@code COPY SL DX; JPL I (5ENTR); <size word>} - 5ENTR returns PAST the size word.
 *     A normal exit goes through 5LEAV, which returns to the SECOND word after the caller's
 *     JPL; ERRETURN goes through 5ERET, which returns to the FIRST word, and that word is
 *     real code (a jump to the ROUTINEERROR group).</li>
 * <li>ASSEMBLER-500:PROG (a runtime of its own, not in any manual we have): the prologue is
 *     {@code STF -3,B; COPY SL DD; JPL I 6,B; <size word>}; the return address is kept at
 *     frame+5 and the routine moves it on with {@code MIN 5,B} once for every inline
 *     parameter word it reads, so those words are DATA.</li>
 * </ul>
 * Neither rule is written in here. Both come out of running the runtime's code.
 *
 * <p>Abstract values: a 16-bit constant, "entry L + n", "entry B + n", or unknown. Memory
 * cells are tracked by constant word address or by "entry B + n". Anything the tracker does
 * not model becomes unknown - and an exit through an unknown address makes the whole result
 * "unknown", so nothing is changed in the listing on a guess.</p>
 *
 * <p>Assumptions, each one stated where it is used:</p>
 * <ol>
 * <li>A constant-address load reads the loaded image. The image is the program's initial
 *     contents; a cell the program rewrites before this point would read wrong.
 *     (1b) So a value worked out from such an image word only stands for an ADDRESS (a
 *     pointer, a call or jump target). A conditional jump that tests it goes both ways, because
 *     the word may be a variable the program has written by then. Only the start code decides
 *     such a test by the image value: it runs right after loading, when the image is memory.
 *     Measured 2026-11-08 in TPE-MON, see {@code Val.img}.</li>
 * <li>"entry L + n" and "entry B + n" are taken as non-zero when compared with zero. They are
 *     a return address and a frame pointer; neither is zero in a running program.</li>
 * <li>A store through an unknown pointer forgets every constant-address cell, but keeps the
 *     frame cells ("entry B + n", and B-128..B+127 when B is a constant, as in the start
 *     code). Keeping them is not proven; without it no frame-based
 *     return could ever be followed.</li>
 * <li>A call whose summary is "returns, B restored" forgets all registers except B and all
 *     constant-address cells, and keeps the frame cells (same reasoning as 3).</li>
 * <li>Frame facts: the constant cells at B+1..B+15 when the start code makes its first call
 *     are taken to hold the same values in every frame. ASSEMBLER-500's entry routine copies
 *     B+6..B+8 into each new frame, which is where this comes from; the summary of the entry
 *     routine does NOT prove it for every program.</li>
 * <li>A cell of the entry frame (B-128..B+127) that this path has not written still holds
 *     its entry value, which is a symbol of its own ("[B0+k]"). Cells measured from
 *     different symbols are taken not to overlap. PLANC needs this: 5ENTR places the new
 *     frame at the caller's FREES cell + 128, a value no summary can know as a number.</li>
 * <li>A routine that cannot be followed to its end but starts by calling PLANC's 5ENTR /
 *     5INIT returns the PLANC way: to call+1 (5ERET) or call+2 (5LEAV). Chosen by Ronny
 *     2026-11-07 for routines with a call through a routine variable; see
 *     {@code plancRule}.</li>
 * <li>A path that runs into a word that this same summary has already loaded as a constant
 *     from the image (assumption 1) is a path that never happens, and is dropped. Measured
 *     2026-11-07 in ASSEMBLER-500: `MIN ,B 11` (octal 015301) and `MIN ,B 5` (015324) skip
 *     onto 0x1ad6, a constant the routine loads with LDX at 0x1aa7, followed by its call
 *     pointers; only when a counter that starts at 1 and counts up reaches zero. Following it
 *     ran the table as STZ/STT instructions into the next routine's prologue. Ghidra's
 *     references were not used: when the first summaries run, most of the code is not in
 *     the listing yet. See {@code loadedWords}.</li>
 * <li>A call to an address the tracker cannot know (a routine taken from a table at run time)
 *     made from a frame that holds the start code's entry and return routines at B+6 and B+7
 *     (the cells ASSEMBLER-500's entry routine copies into every new frame, 0x1477/0x1478)
 *     returns the way that runtime returns: to call+1 or call+2, B and the frame cells kept,
 *     the rest forgotten as in 4. Chosen by Ronny 2026-11-08 for ASSEMBLER-500's handler
 *     call at 0x1ba9 (octal 015651 {@code JPL I ,B 66}), whose following words jump to "done"
 *     and back into the loop. See {@code runtimeRule}.</li>
 * </ol>
 */
final class ND100ReturnTracker {

	/** Where an abstract value is measured from. */
	private static final int UNKNOWN = -1;
	private static final int CONST = 0;
	private static final int ENTRY_L = 1;
	private static final int ENTRY_B = 2;
	/**
	 * Some bits known, the rest not: off holds the known bits, unk marks the unknown ones.
	 * Needed for the status register: the spec writes one flag as
	 * "STS = (STS AND mask) OR bit", and with the rest of STS unknown the carry that the
	 * stack check tests would otherwise be lost too. Not usable as an address, so isKnown()
	 * is false for it.
	 */
	private static final int PARTIAL = 3;
	/**
	 * "What cell entry B + k held when the routine was entered", for k = -128..127 (the cells a
	 * B-relative instruction reaches). Base = ENTRY_CELL0 + k + 128. PLANC's 5ENTR builds the
	 * new frame from the caller's FREES cell (B-176 octal), so the new B is one of these + 128.
	 */
	private static final int ENTRY_CELL0 = 16;
	/**
	 * B as PLANC's 5ENTR / 5INIT leave it: the caller's FREES cell (B-176 octal, -126) + 128
	 * (octal 200). ND-60.117.5 pages 291-294; measured in CHAT.PROG's 5ENTR at 0xd096.
	 */
	private static final Val PLANC_NEW_FRAME = new Val(ENTRY_CELL0 + (-126) + 128, 128);

	/** Instruction visits allowed while summarising one routine (inlined code counts). */
	private static final int STEP_BUDGET = 20000;
	/** How many runtime routines may be inlined inside each other. */
	private static final int MAX_INLINE_DEPTH = 12;
	/** Different states kept apart at a place reached by a backward jump (a loop) before merging. */
	private static final int MAX_STATES_PER_PLACE = 4;
	/** Different states kept apart at one place reached by a forward jump or fall-through. */
	private static final int MAX_PATHS_PER_PLACE = 64;
	/** Summaries larger than this are not trusted as inline-parameter counts. */
	static final int MAX_RETURN_OFFSET = 32;

	/**
	 * One abstract value. Immutable. A constant keeps its full width (p-code widens values,
	 * e.g. RADD adds in 4 bytes to get the carry), and {@link #write} cuts it to the size of
	 * the varnode it lands in. An "entry + n" value is exact in its LOW 16 BITS only: after a
	 * widening its upper bits are unknown, so anything that looks at them (a carry, a shift
	 * right) gives unknown.
	 */
	static final class Val {
		final int base;
		final long off;
		/** PARTIAL only: the bits whose value is not known. */
		final long unk;
		/**
		 * The value was worked out (wholly or partly) from a word of the loaded image that this
		 * path did not write itself - assumption 1b. Such a value is still used as an address
		 * (a pointer, a call target), but a conditional jump that tests it goes both ways: the
		 * program may have written that word before this code runs. Measured 2026-11-08 in
		 * TPE-MON: routine 0x2e6c tests the flag word 0x6a0e (0 in the image, written by the
		 * program at 0x2555, 0x258e, 0x25c2, 0x2e71 and 0x31c9), and deciding that test from the
		 * image value dropped the routine's error return (5ERET) and with it the ROUTINEERROR
		 * code of every caller (0x2f3c, 0x5bbf).
		 */
		final boolean img;

		static final Val TOP = new Val(UNKNOWN, 0);

		Val(int base, long off) {
			this(base, off, false);
		}

		private Val(int base, long off, boolean img) {
			this.base = base;
			this.off = base == UNKNOWN ? 0 : base == CONST ? off : (off & 0xFFFF);
			this.unk = 0;
			this.img = img && base != UNKNOWN;
		}

		private Val(long known, long unk, boolean img) {
			this.base = PARTIAL;
			this.off = known & ~unk;
			this.unk = unk;
			this.img = img;
		}

		/** This value, marked as worked out from an image word (see {@link #img}). */
		Val fromImage() {
			if (img || base == UNKNOWN) {
				return this;
			}
			return base == PARTIAL ? new Val(off, unk, true) : new Val(base, off, true);
		}

		/** {@code r}, marked as coming from the image when any of {@code a}, {@code b} is. */
		static Val taint(Val r, Val a, Val b) {
			return (a.img || (b != null && b.img)) ? r.fromImage() : r;
		}

		/**
		 * A value from known bits and an unknown-bit mask, cut to {@code mask}: a constant when
		 * every bit is known, unknown when none is.
		 */
		static Val bits(long val, long unk, long mask) {
			unk &= mask;
			val &= mask & ~unk;
			if (unk == 0) {
				return new Val(CONST, val);
			}
			if (unk == mask) {
				return TOP;
			}
			return new Val(val, unk, false);
		}

		/** The known bits (0 where unknown). */
		long bitVal() {
			return base == CONST || base == PARTIAL ? off : 0;
		}

		/** The unknown bits: none for a constant, all for anything but a constant or PARTIAL. */
		long bitUnk() {
			return base == CONST ? 0 : base == PARTIAL ? unk : -1L;
		}

		boolean hasBits() {
			return base == CONST || base == PARTIAL;
		}

		/** The low 16 bits: a word address or a word value. */
		int w() {
			return (int) (off & 0xFFFF);
		}

		static Val c(long v) {
			return new Val(CONST, (int) v);
		}

		boolean isConst() {
			return base == CONST;
		}

		boolean isKnown() {
			return base != UNKNOWN && base != PARTIAL;
		}

		Val plus(int n) {
			return !isKnown() ? TOP : new Val(base, off + n, img);
		}

		@Override
		public boolean equals(Object o) {
			if (!(o instanceof Val)) {
				return false;
			}
			Val v = (Val) o;
			return v.base == base && v.off == off && v.unk == unk && v.img == img;
		}

		@Override
		public int hashCode() {
			return base * 65537 + (int) (off ^ (off >>> 32)) + 31 * (int) unk + (img ? 7 : 0);
		}

		@Override
		public String toString() {
			switch (base) {
				case CONST:
					return String.format("%04x", off);
				case ENTRY_L:
					return "L0+" + off;
				case ENTRY_B:
					return "B0+" + (short) off;
				case UNKNOWN:
					return "?";
				case PARTIAL:
					return String.format("bits(%x, unknown %x)", off, unk);
				default:
					return "[B0+" + (base - ENTRY_CELL0 - 128) + "]+" + (short) off;
			}
		}
	}

	/** Machine state: registers, temporaries and memory cells. */
	static final class State {
		final Map<Long, Val> regs = new HashMap<>();
		/** key = base << 16 | word offset; base CONST or ENTRY_B. */
		final Map<Integer, Val> mem = new HashMap<>();
		/** Number of inlined calls this path is inside now (the size of the stack below). */
		int depth;
		/** Address of the call site that inlined the code being run, or -1 at the top. */
		long context = -1;
		/**
		 * The inline stack: for each level, the routine that was inlined, the word after the
		 * call that inlined it (its return point is that word + k), and the context to go back
		 * to. A level is popped when the path jumps back to its return point.
		 */
		long[] inlTarget = new long[MAX_INLINE_DEPTH];
		long[] inlNext = new long[MAX_INLINE_DEPTH];
		long[] inlContext = new long[MAX_INLINE_DEPTH];

		State copy() {
			State s = new State();
			s.regs.putAll(regs);
			s.mem.putAll(mem);
			s.depth = depth;
			s.context = context;
			System.arraycopy(inlTarget, 0, s.inlTarget, 0, depth);
			System.arraycopy(inlNext, 0, s.inlNext, 0, depth);
			System.arraycopy(inlContext, 0, s.inlContext, 0, depth);
			return s;
		}

		/** True if {@code target} is already being inlined on this path. */
		boolean inlining(long target) {
			for (int i = 0; i < depth; i++) {
				if (inlTarget[i] == target) {
					return true;
				}
			}
			return false;
		}

		/** Pops every inline level whose return point is {@code t} (an inlined return). */
		void popReturnsTo(long t) {
			while (depth > 0) {
				long k = (t - inlNext[depth - 1]) & 0xFFFF;
				if (k > MAX_RETURN_OFFSET) {
					return;
				}
				depth--;
				context = inlContext[depth];
			}
		}

		/** How many registers and memory cells differ between this state and {@code o}. */
		int difference(State o) {
			int d = countDiff(regs, o.regs) + countDiff(o.regs, regs);
			return d + countDiff(mem, o.mem) + countDiff(o.mem, mem);
		}

		private static <K> int countDiff(Map<K, Val> a, Map<K, Val> b) {
			int d = 0;
			for (Map.Entry<K, Val> e : a.entrySet()) {
				if (!e.getValue().equals(b.get(e.getKey()))) {
					d++;
				}
			}
			return d;
		}

		/** Joins {@code o} into this state. Returns true if this state changed. */
		boolean join(State o) {
			boolean changed = joinMap(regs, o.regs);
			changed |= joinMem(mem, o.mem);
			return changed;
		}

		/**
		 * Joins memory. Unlike registers, a MISSING cell is not "unknown": it means "still what
		 * it held at entry" (an entry-frame cell) or "the loaded image" (a constant address).
		 * So a cell that differs, or is present on one side only, becomes an explicit
		 * {@link Val#TOP} instead of being dropped.
		 */
		private static boolean joinMem(Map<Integer, Val> mine, Map<Integer, Val> other) {
			boolean changed = false;
			List<Integer> top = new ArrayList<>();
			for (Map.Entry<Integer, Val> e : mine.entrySet()) {
				Val v = other.get(e.getKey());
				if (e.getValue().isKnown() && (v == null || !v.equals(e.getValue()))) {
					top.add(e.getKey());
				}
			}
			for (Map.Entry<Integer, Val> e : other.entrySet()) {
				if (!mine.containsKey(e.getKey())) {
					top.add(e.getKey());
				}
			}
			for (int i = 0; i < top.size(); i++) {
				mine.put(top.get(i), Val.TOP);
				changed = true;
			}
			return changed;
		}

		private static <K> boolean joinMap(Map<K, Val> mine, Map<K, Val> other) {
			boolean changed = false;
			List<K> drop = new ArrayList<>();
			for (Map.Entry<K, Val> e : mine.entrySet()) {
				Val v = other.get(e.getKey());
				if (v == null || !v.equals(e.getValue())) {
					drop.add(e.getKey());
				}
			}
			for (int i = 0; i < drop.size(); i++) {
				mine.remove(drop.get(i));
				changed = true;
			}
			return changed;
		}

		/**
		 * Forgets the constant-address cells, except the frame of {@code b} when B itself is a
		 * constant (the start code's frame): those are frame cells too, only at a fixed
		 * address, and assumptions 3 and 4 keep frame cells. The kept window is what a
		 * B-relative instruction can reach, B-128..B+127.
		 */
		void forgetConstCells(Val b) {
			boolean keepFrame = b != null && b.isConst();
			long lo = keepFrame ? b.w() - 128 : 0;
			mem.keySet().removeIf(k -> {
				if ((k >>> 16) != CONST) {
					return false;
				}
				if (!keepFrame) {
					return true;
				}
				long d = ((k & 0xFFFF) - lo) & 0xFFFF;
				return d > 255;
			});
		}
	}

	/** What a routine does with the return address it was entered with. */
	static final class Summary {
		/** The k values in "returns to entry L + k". */
		final TreeSet<Integer> returns = new TreeSet<>();
		/** True if some exit leaves B different from what it was at entry. */
		boolean changesB;
		/** Some exit went to an address the tracker could not work out. */
		boolean unknownExit;
		/** Ran out of steps. */
		boolean budgetHit;
		/** A path was cut because the routine calls itself (directly or not). */
		boolean recursionCut;
		/**
		 * Some exit jumps to an address it read from the CALLER's frame (an entry-frame cell),
		 * not to its own return address: PLANC's 5LEAV / 5ERET return for the routine that
		 * called them. Such an exit never comes back to the word after this call.
		 */
		boolean leavesThroughFrame;
		/**
		 * For the exits counted in {@link #leavesThroughFrame} that this routine's OWN code makes
		 * (not code of a routine it calls and the tracker followed): which cell of the caller's
		 * frame the address came from and where the jump lands relative to it, as "cell+n"
		 * (cell = offset from B, -128 is PLANC's LINK). Measured 2026-11-08 in TPE-MON (0x6664,
		 * 0x666a) and CHAT.PROG (0xd0ad, 0xd0b3), the same code in both: LINK holds the address
		 * two words after the caller's call, 5LEAV jumps to LINK ("-128+0") and 5ERET first
		 * decrements LINK, so it lands on the error slot ("-128+-1").
		 */
		final TreeSet<String> frameExits = new TreeSet<>();
		/** Some exit leaves B at the caller's FREES cell + 128: PLANC's 5ENTR / 5INIT. */
		boolean plancEntry;
		/** Not followed to its end: the PLANC return rule was assumed (assumption 7). */
		boolean assumedPlanc;
		/** A call to an unknown target was taken to return the runtime's way (assumption 9). */
		boolean assumedRuntime;
		/** First reason the result is not clean, for the log. */
		String why;

		/** Same answer for a caller: same returns and the same flags. */
		boolean sameAs(Summary o) {
			return returns.equals(o.returns) && changesB == o.changesB
				&& unknownExit == o.unknownExit && budgetHit == o.budgetHit
				&& recursionCut == o.recursionCut && leavesThroughFrame == o.leavesThroughFrame
				&& plancEntry == o.plancEntry && assumedPlanc == o.assumedPlanc
				&& frameExits.equals(o.frameExits)
				&& assumedRuntime == o.assumedRuntime;
		}

		boolean isUsable() {
			return !unknownExit && !budgetHit;
		}

		/** A plain call: returns, all exits at one place or several, and B is put back. */
		boolean isClean() {
			return isUsable() && !returns.isEmpty() && !changesB && !leavesThroughFrame;
		}

		boolean neverReturns() {
			return isUsable() && !recursionCut && returns.isEmpty();
		}

		void fail(String reason, boolean budget) {
			if (budget) {
				budgetHit = true;
			}
			else {
				unknownExit = true;
			}
			if (why == null) {
				why = reason;
			}
		}

		@Override
		public String toString() {
			if (!isUsable()) {
				return "unknown (" + why + ")";
			}
			if (returns.isEmpty()) {
				return recursionCut ? "no return found (recursion cut)"
					: leavesThroughFrame ? "leaves through the caller's frame" : "never returns";
			}
			return "returns to L+" + returns + (changesB ? ", B changed" : "")
				+ (assumedPlanc ? " (PLANC rule assumed)" : "")
				+ (assumedRuntime ? " (runtime rule assumed for a call to an unknown routine)" : "");
		}
	}

	private final Program program;
	private final Memory memory;
	private final AddressSpace ram;
	private final int ramId;
	private final PseudoDisassembler pdis;
	private final long regL;
	private final long regB;
	private final long regA;
	private final long regX;
	private final boolean bigEndian;
	private final int regSizeL;

	private final Map<Long, PseudoInstruction> decoded = new HashMap<>();
	private final Set<Long> undecodable = new HashSet<>();
	private final Map<Long, Summary> summaries = new HashMap<>();
	/**
	 * The current (not final) answer of every routine in the computation in progress; see
	 * {@link #summarize}.
	 */
	private final Map<Long, Summary> assumed = new HashMap<>();
	/** For each routine, the routines whose run read its current answer. */
	private final Map<Long, Set<Long>> users = new HashMap<>();
	/** Routines whose answer read something that has changed since: to be run again. */
	private final Set<Long> dirty = new LinkedHashSet<>();
	/** Every routine given a current answer in the computation in progress. */
	private final Set<Long> touched = new HashSet<>();
	/** The routines being run now, innermost first. */
	private final ArrayDeque<Long> runStack = new ArrayDeque<>();
	/** Runs allowed per routine, on average, for the answers of routines that call each other to settle. */
	private static final int MAX_ROUNDS = 8;
	private final Set<Long> inProgress = new HashSet<>();
	/** Frame cells every frame is taken to carry (assumption 5): B offset -> value. */
	private final Map<Integer, Val> frameFacts = new HashMap<>();
	/** True while {@link #learnFrameFacts} runs: calls are followed into, not summarised. */
	private boolean startMode;

	ND100ReturnTracker(Program program) {
		this.program = program;
		this.memory = program.getMemory();
		this.ram = program.getAddressFactory().getDefaultAddressSpace();
		this.ramId = ram.getSpaceID();
		this.pdis = new PseudoDisassembler(program);
		Register l = program.getRegister("L");
		Register b = program.getRegister("B");
		this.regL = l.getOffset();
		this.regSizeL = l.getMinimumByteSize();
		this.regB = b.getOffset();
		this.regA = program.getRegister("A").getOffset();
		this.regX = program.getRegister("X").getOffset();
		this.bigEndian = program.getLanguage().isBigEndian();
	}

	Map<Integer, Val> getFrameFacts() {
		return frameFacts;
	}

	// ---------------------------------------------------------------- addresses

	Address wordAddr(long word) {
		return ram.getAddress(word & 0xFFFF, true);
	}

	static long word(Address a) {
		return a.getAddressableWordOffset();
	}

	/**
	 * Image words loaded as constants during the run in progress (assumption 8). Saved and
	 * restored around a nested run.
	 */
	private Set<Long> loadedWords = new HashSet<>();

	private PseudoInstruction decode(long w) {
		PseudoInstruction pi = decoded.get(w);
		if (pi != null || undecodable.contains(w)) {
			return pi;
		}
		try {
			Address a = wordAddr(w);
			if (!memory.contains(a) || !memory.getBlock(a).isInitialized()) {
				undecodable.add(w);
				return null;
			}
			pi = pdis.disassemble(a);
		}
		catch (Exception e) {
			pi = null;
		}
		if (pi == null) {
			undecodable.add(w);
		}
		else {
			decoded.put(w, pi);
		}
		return pi;
	}

	private Val readImageWord(long w) {
		try {
			Address a = wordAddr(w);
			MemoryBlock blk = memory.getBlock(a);
			if (blk == null || !blk.isInitialized()) {
				return Val.TOP;
			}
			return Val.c(Short.toUnsignedInt(memory.getShort(a)));
		}
		catch (MemoryAccessException e) {
			return Val.TOP;
		}
	}

	// ---------------------------------------------------------------- frame facts

	/**
	 * Runs the start code from {@code entry} along one path, following calls INTO the called
	 * code (the start code may call setup routines before B is set). At every call it looks
	 * at B: the first call where B is a constant and B+1..B+15 hold constant addresses gives
	 * the frame facts every frame is taken to inherit (assumption 5 in the class comment).
	 *
	 * @return true if frame facts were found
	 */
	boolean learnFrameFacts(Address entry) {
		State st = new State();
		long w = word(entry);
		String stop = "ran 2000 instructions";
		// The last instructions walked, for the log when no facts are found.
		ArrayDeque<String> trail = new ArrayDeque<>();
		startMode = true;
		try {
			for (int steps = 0; steps < 2000; steps++) {
				PseudoInstruction pi = decode(w);
				if (pi == null) {
					stop = "no instruction at " + wordAddr(w);
					break;
				}
				trail.add(wordAddr(w) + " " + pi);
				if (trail.size() > 40) {
					trail.poll();
				}
				if (hasCall(pi)) {
					Val b = st.regs.get(key(regB, 2));
					trail.add("[B=" + (b == null ? "?" : b) + " A=" + st.regs.get(key(regA, 2)) + "]");
					if (b != null && b.isConst()) {
						for (int k = 1; k <= 15; k++) {
							Val v = st.mem.get(memKey(CONST, b.w() + k));
							if (v != null && v.isConst() && memory.contains(wordAddr(v.w()))) {
								frameFacts.put(k, v);
							}
						}
						if (!frameFacts.isEmpty()) {
							Msg.info(this, "ND-100 return tracker: start code from " + entry
								+ " has B=" + b + " at the call at " + wordAddr(w)
								+ "; frame facts (B offset=value) " + frameFacts);
							return true;
						}
					}
				}
				List<Step> next = new ArrayList<>();
				Summary scratch = new Summary();
				execute(pi, st, scratch, next, -1, true);
				if (next.size() != 1) {
					stop = (next.isEmpty() ? "path ended" : "path splits") + " at " + wordAddr(w)
						+ (scratch.why != null ? " (" + scratch.why + ")" : "");
					break;
				}
				st = next.get(0).state;
				w = next.get(0).target;
			}
		}
		finally {
			startMode = false;
		}
		Msg.info(this, "ND-100 return tracker: no frame facts from the start code at " + entry
			+ ": " + stop + "; last instructions walked: " + String.join(" | ", trail));
		return false;
	}

	private static boolean hasCall(PseudoInstruction pi) {
		PcodeOp[] ops = pi.getPcode();
		for (int i = 0; i < ops.length; i++) {
			int opc = ops[i].getOpcode();
			if (opc == PcodeOp.CALL || opc == PcodeOp.CALLIND) {
				return true;
			}
		}
		return false;
	}

	// ---------------------------------------------------------------- summaries

	/**
	 * The summary of the routine starting at word address {@code target}.
	 *
	 * <p>Routines that call each other (recursion, direct or through others) are worked out
	 * together: every routine reached gets a current answer in {@link #assumed}, starting from
	 * "returns nowhere". A routine that reads another's current answer is recorded as its user;
	 * when an answer changes, its users are run again. This repeats until no answer changes:
	 * the least answers that agree with the code, so a return found this way is reached by a
	 * finite run of the program. Then every answer worked out in this computation is final.</p>
	 *
	 * <p>Why not one routine at a time: the earlier version ran each recursive routine in rounds
	 * and threw away every inner answer whenever an outer routine started a new round. With
	 * recursion 10-15 routines deep in TPE-MON, inner routines (0x2e6c, 0x5d2e, 0x5bb3) were
	 * worked out hundreds of times each and one import ran for hours (measured 2026-11-08).
	 * Here a routine is run again only when an answer it actually read has changed.</p>
	 */
	Summary summarize(long target) {
		target &= 0xFFFF;
		Summary s = summaries.get(target);
		if (s != null) {
			return s;
		}
		Long caller = runStack.peek();
		if (caller != null) {
			users.computeIfAbsent(target, k -> new HashSet<>()).add(caller);
		}
		Summary cur = assumed.get(target);
		if (cur != null) {
			return cur; // being worked out (recursion) or worked out but not final yet
		}
		boolean outermost = runStack.isEmpty();
		assumed.put(target, new Summary());
		touched.add(target);
		evaluate(target);
		if (!outermost) {
			return assumed.get(target);
		}
		// Run again every routine whose answer read something that has since changed.
		int budget = MAX_ROUNDS * touched.size() + 64;
		while (!dirty.isEmpty()) {
			if (--budget < 0) {
				for (Long t : touched) {
					assumed.get(t).fail("recursion did not settle", false);
				}
				break;
			}
			Long t = dirty.iterator().next();
			dirty.remove(t);
			evaluate(t);
		}
		for (Long t : touched) {
			Summary f = assumed.get(t);
			summaries.put(t, f);
			Msg.debug(this, "ND-100 return tracker: " + wordAddr(t) + " " + f);
		}
		assumed.clear();
		users.clear();
		touched.clear();
		dirty.clear();
		return summaries.get(target);
	}

	/** Runs one routine with the current answers of the others, and records what changed. */
	private void evaluate(long target) {
		runStack.push(target);
		inProgress.add(target);
		Summary s;
		try {
			s = run(target);
			if (!s.isUsable()) {
				Summary p = plancRule(target, s);
				if (p != null) {
					s = p;
				}
			}
		}
		finally {
			runStack.pop();
			inProgress.remove(target);
		}
		Summary old = assumed.get(target);
		if (old == null || !s.sameAs(old)) {
			assumed.put(target, s);
			Set<Long> u = users.get(target);
			if (u != null) {
				dirty.addAll(u);
			}
		}
	}

	/**
	 * Assumption 7 (chosen by Ronny 2026-11-07): a routine that cannot be followed to its end,
	 * but whose entry calls PLANC's 5ENTR / 5INIT, returns the PLANC way - 5LEAV to call+2 or
	 * 5ERET to call+1 (ND-60.117.5 pages 291-294). Typical cause: a call through a routine
	 * variable taken from data (CHAT.PROG 0x9a02, {@code JPL ,X 0}). The entry routine is
	 * recognised by what it does, not by its address: its summary leaves B at the caller's
	 * FREES cell + 128, which is where the manual says the new frame goes.
	 *
	 * @return the assumed summary, or null if the routine does not start that way
	 */
	private Summary plancRule(long target, Summary failed) {
		if (plancEntryCall(target) < 0) {
			return null;
		}
		Summary s = new Summary();
		s.returns.add(0);
		s.returns.add(1);
		s.assumedPlanc = true;
		s.why = "PLANC rule assumed (" + failed.why + ")";
		return s;
	}

	/**
	 * If the routine at {@code target} starts the PLANC way - one of its first three
	 * instructions calls a routine whose summary is PLANC's 5ENTR / 5INIT, e.g.
	 * {@code COPY SL DX; JPL I (5ENTR)} - the word address of that call; otherwise -1.
	 */
	long plancEntryCall(long target) {
		long w = target;
		for (int n = 0; n < 3; n++) {
			PseudoInstruction pi = decode(w);
			if (pi == null) {
				return -1;
			}
			if (pi.getFlowType().isCall()) {
				long t = callTarget(pi);
				if (t < 0 || isInProgress(t)) {
					return -1;
				}
				return summarize(t).plancEntry ? w : -1;
			}
			w += pi.getLength() / 2;
		}
		return -1;
	}

	boolean isInProgress(long target) {
		return inProgress.contains(target & 0xFFFF);
	}

	private State entryState() {
		State st = new State();
		st.regs.put(key(regL, regSizeL), new Val(ENTRY_L, 0));
		st.regs.put(key(regB, 2), new Val(ENTRY_B, 0));
		for (Map.Entry<Integer, Val> e : frameFacts.entrySet()) {
			st.mem.put(memKey(ENTRY_B, e.getKey()), e.getValue());
		}
		return st;
	}

	/** One step out of an instruction: go to an address, or the path ends. */
	private static final class Step {
		static final int GOTO = 0;
		final int kind;
		final long target;
		final State state;
		/**
		 * True for a direct jump to a fixed address, a conditional branch or a fall-through.
		 * Only these can close a loop; an indirect jump (a return, a jump through a frame cell)
		 * or a call into a runtime routine at a lower address is not a loop.
		 */
		boolean isDirect;
		/** True when a direct step goes back to a lower or equal address: a loop can close here. */
		boolean back;

		static Step direct(long target, State state) {
			Step s = new Step(target, state);
			s.isDirect = true;
			return s;
		}

		Step(long target, State state) {
			this.kind = GOTO;
			this.target = target;
			this.state = state;
		}
	}

	private Summary run(long start) {
		Set<Long> outer = loadedWords;
		loadedWords = new HashSet<>();
		try {
			return runInner(start);
		}
		finally {
			loadedWords = outer;
		}
	}

	private Summary runInner(long start) {
		Summary sum = new Summary();
		ArrayDeque<Step> work = new ArrayDeque<>();
		// visited key: word address and the inlining call site, so a runtime routine
		// inlined from two places does not mix the two return addresses.
		//
		// Merging loses values that differ: a routine with one exit to L+0 and one that first
		// steps the return address on (MIN 5,B) reaches the shared return routine with two
		// return addresses, and one merged state would only say "unknown" (measured on
		// ASSEMBLER-500's 0x1a9c and 0x1b84, 2026-11-07, where loop counters gave more than 16
		// variants at the return routine). So states are merged only where the code jumps back
		// (where a loop can close, which is what bounds the work): there at most
		// MAX_STATES_PER_PLACE are kept. Anywhere else up to MAX_PATHS_PER_PLACE stay apart.
		// When a limit is reached, a state is merged into the one it differs from least.
		Map<String, List<State>> seen = new HashMap<>();
		work.add(new Step(start, entryState()));
		int steps = 0;
		while (!work.isEmpty()) {
			Step s = work.poll();
			String vkey = s.target + "@" + s.state.context;
			List<State> olds = seen.get(vkey);
			State st;
			if (olds == null) {
				olds = new ArrayList<>();
				seen.put(vkey, olds);
				st = s.state.copy();
				olds.add(st.copy());
			}
			else {
				boolean covered = false;
				for (int i = 0; i < olds.size() && !covered; i++) {
					// Already covered when joining it in would change nothing.
					covered = !olds.get(i).copy().join(s.state);
				}
				if (covered) {
					continue;
				}
				int limit = s.back ? MAX_STATES_PER_PLACE : MAX_PATHS_PER_PLACE;
				if (olds.size() < limit) {
					st = s.state.copy();
					olds.add(st.copy());
				}
				else {
					// Merge into the state it differs from least, so states that differ only
					// in, say, a loop counter merge, while two different return addresses
					// stay apart.
					State best = olds.get(0);
					int bestDiff = Integer.MAX_VALUE;
					for (int i = 0; i < olds.size(); i++) {
						int d = olds.get(i).difference(s.state);
						if (d < bestDiff) {
							bestDiff = d;
							best = olds.get(i);
						}
					}
					best.join(s.state);
					st = best.copy();
				}
			}
			if (++steps > STEP_BUDGET) {
				sum.fail("more than " + STEP_BUDGET + " instructions", true);
				return sum;
			}
			if (loadedWords.contains((long) s.target)) {
				continue; // assumption 8
			}
			PseudoInstruction pi = decode(s.target);
			if (pi == null) {
				sum.fail("no instruction at " + wordAddr(s.target), false);
				return sum;
			}
			List<Step> next = new ArrayList<>();
			execute(pi, st, sum, next, s.target, false);
			for (int i = 0; i < next.size(); i++) {
				next.get(i).back = next.get(i).isDirect && next.get(i).target <= s.target;
			}
			if (!sum.isUsable()) {
				return sum;
			}
			work.addAll(next);
		}
		return sum;
	}

	// ---------------------------------------------------------------- p-code

	private static long key(long regOffset, int size) {
		return (regOffset << 8) | size;
	}

	private static int memKey(int base, long wordOff) {
		return (base << 16) | (int) (wordOff & 0xFFFF);
	}

	/** Reads a varnode. Registers and temporaries need an exact match of offset and size. */
	private Val read(Varnode v, State st, Map<Long, Val> uniq) {
		if (v.isConstant()) {
			return Val.c(v.getOffset());
		}
		if (v.isRegister()) {
			return readPiece(st.regs, v);
		}
		if (v.isUnique()) {
			return readPiece(uniq, v);
		}
		if (v.isAddress() && v.getAddress().getAddressSpace().getSpaceID() == ramId
				&& v.getSize() == 2) {
			return loadCell(Val.c(word(v.getAddress())), st);
		}
		return Val.TOP;
	}

	/**
	 * Reads a register or temporary. Exact match first; otherwise a piece of a wider stored
	 * value. SLEIGH does this a lot: AAB adds in 4 bytes and copies B back out as
	 * (unique, 0x8e02, 2) - the low half of the 4-byte temporary at 0x8e00, because the
	 * language is big-endian and the low half sits at the higher offset.
	 */
	private Val readPiece(Map<Long, Val> map, Varnode v) {
		Val x = map.get(key(v.getOffset(), v.getSize()));
		if (x != null) {
			return x;
		}
		long lo = v.getOffset();
		int size = v.getSize();
		for (Map.Entry<Long, Val> e : map.entrySet()) {
			long o = e.getKey() >>> 8;
			int sz = (int) (e.getKey() & 0xFF);
			if (o > lo || o + sz < lo + size || sz <= size) {
				continue;
			}
			// Bytes between the end of the piece and the end of the stored value.
			int shiftBytes = bigEndian ? (int) ((o + sz) - (lo + size)) : (int) (lo - o);
			Val w = e.getValue();
			if (w.hasBits()) {
				long m = size >= 8 ? -1L : (1L << (size * 8)) - 1;
				return Val.bits(w.bitVal() >>> (shiftBytes * 8), w.bitUnk() >>> (shiftBytes * 8),
					m);
			}
			// An "entry + n" value is exact in its low 16 bits only.
			if (w.isKnown() && shiftBytes == 0 && size >= 2) {
				return w;
			}
			return Val.TOP;
		}
		return Val.TOP;
	}

	private void write(Varnode v, Val x, State st, Map<Long, Val> uniq) {
		if (v == null) {
			return;
		}
		if (x.hasBits() && v.getSize() < 8) {
			x = Val.taint(Val.bits(x.bitVal(), x.bitUnk(), (1L << (v.getSize() * 8)) - 1), x, null);
		}
		if (v.isRegister() || v.isUnique()) {
			// Drop anything that overlaps (e.g. a one-byte flag inside a wider register),
			// so a later piece read cannot see a value this write replaced.
			Map<Long, Val> map = v.isRegister() ? st.regs : uniq;
			long lo = v.getOffset();
			long hi = lo + v.getSize();
			map.keySet().removeIf(k -> {
				long o = k >>> 8;
				long e = o + (k & 0xFF);
				return o < hi && lo < e;
			});
			if (x.isKnown() || x.base == PARTIAL) {
				map.put(key(v.getOffset(), v.getSize()), x);
			}
		}
		else if (v.isAddress() && v.getAddress().getAddressSpace().getSpaceID() == ramId) {
			storeCell(Val.c(word(v.getAddress())), x, v.getSize(), st);
		}
	}

	private Val loadCell(Val ptr, State st) {
		if (!ptr.isKnown()) {
			return Val.TOP;
		}
		Val x = st.mem.get(memKey(ptr.base, ptr.off));
		if (x != null) {
			return x;
		}
		if (ptr.base == CONST) {
			loadedWords.add((long) ptr.w()); // assumption 8
			return readImageWord(ptr.w()).fromImage(); // assumptions 1 and 1b
		}
		short k = (short) ptr.off;
		if (ptr.base == ENTRY_B && k >= -128 && k <= 127) {
			// Never written on this path: still what it held at entry (assumption 6).
			return new Val(ENTRY_CELL0 + k + 128, 0);
		}
		return Val.TOP;
	}

	private void storeCell(Val ptr, Val x, int size, State st) {
		if (!ptr.isKnown()) {
			// assumption 3: an unknown target forgets the constant cells only.
			st.forgetConstCells(st.regs.get(key(regB, 2)));
			return;
		}
		if (size != 2) {
			// Not split into words here: the words it covers become unknown. (An explicit
			// TOP, not a removal: a missing cell means "unchanged since entry".)
			for (int i = 0; i < (size + 1) / 2; i++) {
				st.mem.put(memKey(ptr.base, ptr.off + i), Val.TOP);
			}
			return;
		}
		st.mem.put(memKey(ptr.base, ptr.off), x.isKnown() ? x : Val.TOP);
	}

	private static long sext(long v, int size) {
		if (size >= 8) {
			return v;
		}
		int bits = size * 8;
		v &= (1L << bits) - 1;
		return (v & (1L << (bits - 1))) != 0 ? v - (1L << bits) : v;
	}

	/**
	 * Bit-by-bit results for operands of which only some bits are known (a status flag written
	 * into an otherwise unknown STS). Only operations where a known bit really follows from
	 * known bits: AND (a known 0 gives 0), OR (a known 1 gives 1), shifts by a constant, and
	 * equal / not-equal when a known bit already differs or every bit is known. Returns null
	 * for anything else (the caller then gives unknown).
	 */
	private static Val bitArith(int opc, Val a, Val b, int size, int inSize) {
		long outMask = size >= 8 ? -1L : (1L << (size * 8)) - 1;
		long inMask = inSize >= 8 ? -1L : (1L << (inSize * 8)) - 1;
		long xa = a.bitVal() & inMask;
		long ua = a.bitUnk() & inMask;
		long xb = b.bitVal() & inMask;
		long ub = b.bitUnk() & inMask;
		switch (opc) {
			case PcodeOp.INT_AND: {
				long knownZero = (~ua & ~xa) | (~ub & ~xb);
				return Val.bits(xa & xb, (ua | ub) & ~knownZero, outMask);
			}
			case PcodeOp.INT_OR: {
				long knownOne = (~ua & xa) | (~ub & xb);
				return Val.bits(xa | xb, (ua | ub) & ~knownOne, outMask);
			}
			case PcodeOp.INT_LEFT:
				if (!b.isConst()) {
					return null;
				}
				if (xb >= 64) {
					return Val.c(0);
				}
				return Val.bits(xa << xb, ua << xb, outMask);
			case PcodeOp.INT_RIGHT:
				if (!b.isConst()) {
					return null;
				}
				if (xb >= 64) {
					return Val.c(0);
				}
				return Val.bits(xa >>> xb, ua >>> xb, outMask);
			case PcodeOp.INT_EQUAL:
			case PcodeOp.INT_NOTEQUAL: {
				long knownBoth = ~ua & ~ub & inMask;
				if (((xa ^ xb) & knownBoth) != 0) {
					return Val.c(opc == PcodeOp.INT_NOTEQUAL ? 1 : 0);
				}
				return null;
			}
			default:
				return null;
		}
	}

	private static Val arith(int opc, Val a, Val b, int size, int inSize) {
		long mask = size >= 8 ? -1L : (1L << (size * 8)) - 1;
		if (opc == PcodeOp.INT_ADD) {
			if (a.isConst() && b.isKnown()) {
				return new Val(b.base, b.off + a.off);
			}
			if (b.isConst() && a.isKnown()) {
				return new Val(a.base, a.off + b.off);
			}
			return Val.TOP;
		}
		if (opc == PcodeOp.INT_SUB) {
			if (b.isConst() && a.isKnown()) {
				return new Val(a.base, a.off - b.off);
			}
			if (a.isKnown() && b.isKnown() && a.base == b.base) {
				return Val.c((a.off - b.off) & mask);
			}
			return Val.TOP;
		}
		boolean symbolic = (a.isKnown() && !a.isConst()) || (b.isKnown() && !b.isConst());
		if ((!a.isConst() || !b.isConst()) && !symbolic) {
			Val r = bitArith(opc, a, b, size, inSize);
			if (r != null) {
				return r;
			}
		}
		if (!a.isConst() || !b.isConst()) {
			// assumption 2: a return address or frame pointer is never zero.
			if ((opc == PcodeOp.INT_EQUAL || opc == PcodeOp.INT_NOTEQUAL)
					&& ((a.isKnown() && !a.isConst() && b.isConst() && b.off == 0)
						|| (b.isKnown() && !b.isConst() && a.isConst() && a.off == 0))) {
				return Val.c(opc == PcodeOp.INT_NOTEQUAL ? 1 : 0);
			}
			return Val.TOP;
		}
		int inBits = inSize >= 8 ? 64 : inSize * 8;
		long inMask = inBits == 64 ? -1L : (1L << inBits) - 1;
		long x = a.off & inMask;
		long y = b.off & inMask;
		long sx = sext(a.off, inSize);
		long sy = sext(b.off, inSize);
		switch (opc) {
			case PcodeOp.INT_AND:
				return Val.c(x & y);
			case PcodeOp.INT_OR:
				return Val.c(x | y);
			case PcodeOp.INT_XOR:
				return Val.c(x ^ y);
			case PcodeOp.INT_MULT:
				return Val.c((x * y) & mask);
			case PcodeOp.INT_LEFT:
				return Val.c(y >= 16 ? 0 : (x << y) & mask);
			case PcodeOp.INT_RIGHT:
				return Val.c(y >= 16 ? 0 : x >>> y);
			case PcodeOp.INT_EQUAL:
				return Val.c(x == y ? 1 : 0);
			case PcodeOp.INT_NOTEQUAL:
				return Val.c(x != y ? 1 : 0);
			case PcodeOp.INT_LESS:
				return Val.c(Long.compareUnsigned(x, y) < 0 ? 1 : 0);
			case PcodeOp.INT_LESSEQUAL:
				return Val.c(Long.compareUnsigned(x, y) <= 0 ? 1 : 0);
			case PcodeOp.INT_SLESS:
				return Val.c(sx < sy ? 1 : 0);
			case PcodeOp.INT_SLESSEQUAL:
				return Val.c(sx <= sy ? 1 : 0);
			case PcodeOp.BOOL_AND:
				return Val.c(x & y & 1);
			case PcodeOp.BOOL_OR:
				return Val.c((x | y) & 1);
			case PcodeOp.BOOL_XOR:
				return Val.c((x ^ y) & 1);
			default:
				return Val.TOP;
		}
	}

	/**
	 * Runs one instruction's p-code. Successor addresses go into {@code out}; returns,
	 * unknown exits and calls are recorded in {@code sum}.
	 *
	 * @param firstOnly start-code mode: an undecided conditional branch is not split, the
	 *                  run gives up instead (used only by {@link #learnFrameFacts}).
	 */
	private void execute(PseudoInstruction pi, State st, Summary sum, List<Step> out,
			long here, boolean firstOnly) {
		PcodeOp[] ops = pi.getPcode();
		long next = word(pi.getAddress()) + pi.getLength() / 2;
		runOps(pi, ops, 0, st, new HashMap<>(), sum, out, next, firstOnly);
	}

	private void runOps(PseudoInstruction pi, PcodeOp[] ops, int idx, State st,
			Map<Long, Val> uniq, Summary sum, List<Step> out, long next, boolean firstOnly) {
		int guard = 0;
		while (idx < ops.length) {
			if (++guard > 1000) {
				sum.fail("p-code loop inside " + pi.getAddress(), false);
				return;
			}
			PcodeOp op = ops[idx];
			int opc = op.getOpcode();
			Varnode o = op.getOutput();
			switch (opc) {
				case PcodeOp.COPY:
					write(o, read(op.getInput(0), st, uniq), st, uniq);
					break;
				case PcodeOp.LOAD: {
					Val ptr = read(op.getInput(1), st, uniq);
					boolean isRam = op.getInput(0).getOffset() == ramId;
					Val x = (isRam && o.getSize() == 2) ? loadCell(ptr, st) : Val.TOP;
					write(o, x, st, uniq);
					break;
				}
				case PcodeOp.STORE: {
					boolean isRam = op.getInput(0).getOffset() == ramId;
					if (isRam) {
						Val ptr = read(op.getInput(1), st, uniq);
						storeCell(ptr, read(op.getInput(2), st, uniq), op.getInput(2).getSize(),
							st);
					}
					break;
				}
				case PcodeOp.INT_ZEXT:
				case PcodeOp.INT_SEXT: {
					Val a = read(op.getInput(0), st, uniq);
					Val a0 = a;
					int inSize = op.getInput(0).getSize();
					if (a.isConst()) {
						long m = inSize >= 8 ? -1L : (1L << (inSize * 8)) - 1;
						a = Val.c(opc == PcodeOp.INT_SEXT ? sext(a.off, inSize) : a.off & m);
					}
					else if (a.base == PARTIAL) {
						long m = inSize >= 8 ? -1L : (1L << (inSize * 8)) - 1;
						// Zero-extension adds known zeros; a sign-extension's new bits are
						// only known when the sign bit is, so it gives unknown.
						a = opc == PcodeOp.INT_ZEXT ? Val.bits(a.bitVal(), a.bitUnk(), m) : Val.TOP;
					}
					else if (a.isKnown() && inSize < 2) {
						a = Val.TOP; // an entry value is 16 bits; a byte of it is unknown
					}
					// A widened entry value stays "entry + n" in its low 16 bits.
					write(o, Val.taint(a, a0, null), st, uniq);
					break;
				}
				case PcodeOp.SUBPIECE: {
					Val a = read(op.getInput(0), st, uniq);
					long sh = op.getInput(1).getOffset();
					if (a.hasBits()) {
						long m = o.getSize() >= 8 ? -1L : (1L << (o.getSize() * 8)) - 1;
						write(o, Val.taint(Val.bits(a.bitVal() >>> (sh * 8), a.bitUnk() >>> (sh * 8), m),
							a, null), st, uniq);
					}
					else if (a.isKnown() && sh == 0 && o.getSize() >= 2) {
						write(o, a, st, uniq);
					}
					else {
						write(o, Val.TOP, st, uniq);
					}
					break;
				}
				case PcodeOp.INT_2COMP: {
					Val a = read(op.getInput(0), st, uniq);
					write(o, Val.taint(a.isConst() ? Val.c(-a.off) : Val.TOP, a, null), st, uniq);
					break;
				}
				case PcodeOp.INT_NEGATE: {
					Val a = read(op.getInput(0), st, uniq);
					write(o, Val.taint(a.hasBits() ? Val.bits(~a.bitVal(), a.bitUnk(), -1L) : Val.TOP, a,
						null), st, uniq);
					break;
				}
				case PcodeOp.BOOL_NEGATE: {
					Val a = read(op.getInput(0), st, uniq);
					write(o, Val.taint(a.isConst() ? Val.c(a.off == 0 ? 1 : 0) : Val.TOP, a, null), st,
						uniq);
					break;
				}
				case PcodeOp.INT_ADD:
				case PcodeOp.INT_SUB:
				case PcodeOp.INT_AND:
				case PcodeOp.INT_OR:
				case PcodeOp.INT_XOR:
				case PcodeOp.INT_MULT:
				case PcodeOp.INT_LEFT:
				case PcodeOp.INT_RIGHT:
				case PcodeOp.INT_EQUAL:
				case PcodeOp.INT_NOTEQUAL:
				case PcodeOp.INT_LESS:
				case PcodeOp.INT_LESSEQUAL:
				case PcodeOp.INT_SLESS:
				case PcodeOp.INT_SLESSEQUAL:
				case PcodeOp.BOOL_AND:
				case PcodeOp.BOOL_OR:
				case PcodeOp.BOOL_XOR:
				{
					Val x0 = read(op.getInput(0), st, uniq);
					Val x1 = read(op.getInput(1), st, uniq);
					write(o, Val.taint(arith(opc, x0, x1, o.getSize(), op.getInput(0).getSize()), x0,
						x1), st, uniq);
				}
					break;
				case PcodeOp.BRANCH: {
					Varnode t = op.getInput(0);
					if (t.isConstant()) {
						idx += (int) t.getOffset();
						continue;
					}
					out.add(Step.direct(word(t.getAddress()), st));
					return;
				}
				case PcodeOp.CBRANCH: {
					Val c = read(op.getInput(1), st, uniq);
					Varnode t = op.getInput(0);
					boolean take;
					// Assumption 1b: a test on an image word is not decided by its image value,
					// except in the start code (firstOnly), which runs when the program has just
					// been loaded, so the image IS what memory holds there.
					if (c.isConst() && (!c.img || firstOnly)) {
						take = c.off != 0;
					}
					else if (firstOnly) {
						return; // start code: give up on an undecided branch
					}
					else {
						// Both ways: run the taken side on a copy, carry on with the other.
						State fork = st.copy();
						Map<Long, Val> forkUniq = new HashMap<>(uniq);
						if (t.isConstant()) {
							runOps(pi, ops, idx + (int) t.getOffset(), fork, forkUniq, sum, out,
								next, firstOnly);
						}
						else {
							out.add(Step.direct(word(t.getAddress()), fork));
						}
						idx++;
						continue;
					}
					if (take) {
						if (t.isConstant()) {
							idx += (int) t.getOffset();
							continue;
						}
						out.add(Step.direct(word(t.getAddress()), st));
						return;
					}
					break;
				}
				case PcodeOp.BRANCHIND:
				case PcodeOp.RETURN:
					jumpTo(read(op.getInput(0), st, uniq), st, sum, out, pi);
					return;
				case PcodeOp.CALL:
					call(Val.c(word(op.getInput(0).getAddress())), st, sum, out, pi, next);
					return;
				case PcodeOp.CALLIND:
					call(read(op.getInput(0), st, uniq), st, sum, out, pi, next);
					return;
				default:
					// CALLOTHER, float, anything not modelled: output unknown.
					write(o, Val.TOP, st, uniq);
					break;
			}
			idx++;
		}
		out.add(Step.direct(next, st));
	}

	/**
	 * The address a call instruction calls, worked out from its own p-code with B taken as a
	 * frame that carries the frame facts (so {@code JPL I 6,B} resolves). Returns the word
	 * address, or -1 if it cannot be known.
	 */
	long callTarget(ghidra.program.model.listing.Instruction instr) {
		State st = entryState();
		Map<Long, Val> uniq = new HashMap<>();
		PcodeOp[] ops = instr.getPcode();
		for (int i = 0; i < ops.length; i++) {
			PcodeOp op = ops[i];
			int opc = op.getOpcode();
			Varnode o = op.getOutput();
			if (opc == PcodeOp.CALL) {
				return word(op.getInput(0).getAddress());
			}
			if (opc == PcodeOp.CALLIND) {
				Val t = read(op.getInput(0), st, uniq);
				return t.isConst() ? t.w() : -1;
			}
			if (opc == PcodeOp.COPY) {
				write(o, read(op.getInput(0), st, uniq), st, uniq);
			}
			else if (opc == PcodeOp.LOAD) {
				boolean isRam = op.getInput(0).getOffset() == ramId;
				Val x = (isRam && o.getSize() == 2)
						? loadCell(read(op.getInput(1), st, uniq), st)
						: Val.TOP;
				write(o, x, st, uniq);
			}
			else if (opc == PcodeOp.INT_ADD || opc == PcodeOp.INT_SUB) {
				write(o, arith(opc, read(op.getInput(0), st, uniq),
					read(op.getInput(1), st, uniq), o.getSize(), op.getInput(0).getSize()),
					st, uniq);
			}
			else if (opc == PcodeOp.STORE) {
				continue;
			}
			else {
				write(o, Val.TOP, st, uniq);
			}
		}
		return -1;
	}

	/** An indirect jump or return to {@code t}. */
	private void jumpTo(Val t, State st, Summary sum, List<Step> out, PseudoInstruction pi) {
		if (t.base == ENTRY_L) {
			// The routine is leaving through its own return address.
			if (t.off > MAX_RETURN_OFFSET) {
				sum.fail("returns to L+" + t.off + " at " + pi.getAddress(), false);
				return;
			}
			sum.returns.add(t.w());
			Val b = st.regs.get(key(regB, 2));
			if (b == null || b.base != ENTRY_B || b.off != 0) {
				sum.changesB = true;
			}
			if (PLANC_NEW_FRAME.equals(b)) {
				// B leaves as the caller's FREES cell + 128 (octal 200): PLANC's 5ENTR / 5INIT.
				sum.plancEntry = true;
			}
			return;
		}
		if (t.base >= ENTRY_CELL0) {
			// The address came out of the caller's frame: this exit returns for the caller.
			sum.leavesThroughFrame = true;
			if (st.depth == 0) {
				// Only the routine's own jump: a routine that calls 5LEAV leaves through the
				// frame too, but it is not the runtime routine (CHAT.PROG 0xa541, 2026-11-08).
				sum.frameExits.add((t.base - ENTRY_CELL0 - 128) + "+" + (short) t.off);
			}
			return;
		}
		if (t.isConst()) {
			// An indirect jump to the return point of an inlined call is that call returning:
			// leave its inline level. (A jump within 32 words after the inlining call counts as
			// its return; inlined runtime code lives elsewhere, so a false match would need
			// that code to jump into its caller's next few words.)
			st.popReturnsTo(t.w());
			out.add(new Step(t.w(), st));
			return;
		}
		sum.fail("jump to " + t + " at " + pi.getAddress() + " " + describe(st), false);
	}

	/** B, L and the cells B+0..B+7, for a log line that says why a target was unknown. */
	private String describe(State st) {
		Val b = st.regs.get(key(regB, 2));
		StringBuilder sb = new StringBuilder("[B=" + b + " L=" + st.regs.get(key(regL, regSizeL)));
		if (b != null && b.base == ENTRY_B) {
			for (int i = 0; i <= 7; i++) {
				sb.append(" B+").append(i).append('=')
					.append(st.mem.get(memKey(ENTRY_B, (int) b.off + i)));
			}
		}
		if (b != null && b.isConst()) {
			// A fixed-address frame: list the cells the path holds near it.
			for (int i = -160; i <= 8; i++) {
				Val v = st.mem.get(memKey(CONST, b.w() + i));
				if (v != null) {
					sb.append(" B").append(i >= 0 ? "+" : "").append(i).append('=').append(v);
				}
			}
		}
		Val x = st.regs.get(key(regX, 2));
		sb.append(" X=").append(x);
		if (x != null && x.base == ENTRY_B) {
			for (int i = 0; i <= 5; i++) {
				sb.append(" X+").append(i).append('=')
					.append(st.mem.get(memKey(ENTRY_B, (int) x.off + i)));
			}
		}
		return sb.append(" ctx=").append(st.context).append(" depth=").append(st.depth)
			.append(']').toString();
	}

	/**
	 * Assumption 9: a call to an unknown target from a frame built by the start code's runtime
	 * returns to call+1 or call+2 (L+0, L+1) with B and the frame cells kept. False, and
	 * nothing done, when the frame does not show that runtime or L is not known.
	 */
	private boolean runtimeRule(State st, Summary sum, List<Step> out, PseudoInstruction pi) {
		Val entryRoutine = frameFacts.get(6);
		Val returnRoutine = frameFacts.get(7);
		Val b = st.regs.get(key(regB, 2));
		Val lNow = st.regs.get(key(regL, regSizeL));
		if (startMode || entryRoutine == null || returnRoutine == null || b == null
			|| !b.isKnown() || lNow == null || !lNow.isKnown()) {
			return false;
		}
		if (!entryRoutine.equals(loadCell(b.plus(6), st))
			|| !returnRoutine.equals(loadCell(b.plus(7), st))) {
			return false;
		}
		for (int k = 0; k <= 1; k++) {
			State after = st.copy();
			after.regs.clear();
			after.forgetConstCells(b);
			after.regs.put(key(regB, 2), b);
			jumpTo(lNow.plus(k), after, sum, out, pi);
		}
		sum.assumedRuntime = true;
		return true;
	}

	/** A call to {@code t}; {@code next} is the word after the calling instruction. */
	private void call(Val t, State st, Summary sum, List<Step> out, PseudoInstruction pi,
			long next) {
		if (t.base == ENTRY_L) {
			sum.fail("call through own return address at " + pi.getAddress(), false);
			return;
		}
		if (!t.isConst()) {
			if (runtimeRule(st, sum, out, pi)) {
				return;
			}
			sum.fail("call to " + t + " at " + pi.getAddress() + " " + describe(st), false);
			return;
		}
		long target = t.w();
		if (startMode) {
			out.add(new Step(target, st));
			return;
		}
		// Recursion is handled in summarize(): a routine still being worked out gives its current
		// answer (first "returns nowhere", so on the first run this path ends here), and this
		// routine is run again when that answer changes.
		Summary callee = summarize(target);
		Val lNow = st.regs.get(key(regL, regSizeL));
		if (callee.isClean() && lNow != null && lNow.isKnown()) {
			// assumption 4: a clean call keeps B and the frame cells, forgets the rest.
			Val b = st.regs.get(key(regB, 2));
			for (Integer k : callee.returns) {
				// copy() keeps memory, depth, context and the inline stack; registers go.
				State after = st.copy();
				after.regs.clear();
				after.forgetConstCells(b);
				if (b != null) {
					after.regs.put(key(regB, 2), b);
				}
				jumpTo(lNow.plus(k), after, sum, out, pi);
			}
			if (callee.recursionCut) {
				sum.recursionCut = true;
			}
			if (callee.assumedRuntime) {
				sum.assumedRuntime = true; // this result rests on assumption 9 too
			}
			return;
		}
		if (callee.neverReturns() && !callee.leavesThroughFrame) {
			return;
		}
		// A routine that leaves through the caller's frame (5LEAV, 5ERET) is inlined below:
		// run with this routine's state, its exit jump resolves to this routine's own return.
		// Not a plain call (a runtime entry/exit routine changes B, or its result depends on
		// the caller's frame): run its code here, with this caller's state.
		if (st.inlining(target)) {
			// The same routine is already being inlined on this path (for example the
			// entry routine's stack-overflow path entering a routine that goes through the
			// entry routine again): recursion, not followed.
			sum.recursionCut = true;
			return;
		}
		if (st.depth >= MAX_INLINE_DEPTH) {
			sum.fail("calls nested deeper than " + MAX_INLINE_DEPTH + " at " + pi.getAddress(),
				false);
			return;
		}
		State in = st.copy();
		in.inlTarget[st.depth] = target;
		in.inlNext[st.depth] = next;
		in.inlContext[st.depth] = st.context;
		in.depth = st.depth + 1;
		in.context = word(pi.getAddress());
		out.add(new Step(target, in));
	}
}
