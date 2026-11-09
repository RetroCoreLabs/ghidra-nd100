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

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;

/**
 * Puts what the return tracker found out about PLANC on the listing, so a reader sees the
 * PLANC shape without knowing the runtime: names the runtime routines, marks the inline words
 * after the entry call, and comments the error slot after each call to a PLANC routine.
 *
 * <p>Everything is recognised by what the code DOES (the tracker's summaries), never by an
 * address, so it works on any ND-100 PLANC program. The rules come from ND-60.117.5 Appendix D
 * section 0.2 (pages 291-294):</p>
 * <ul>
 * <li>5ENTR / 5INIT: entry routines. Their summary leaves B at the caller's FREES cell + 128
 *     (the new frame). 5ENTR is followed by one inline word (stack space requirement), 5INIT by
 *     five; the routine returns past them, so the number of inline words is its return offset.</li>
 * <li>5LEAV: normal exit. Returns for its caller through the LINK cell (B-128). LINK holds the
 *     address two words after the caller's call, so 5LEAV jumps to LINK itself, past the error
 *     slot. Measured, not taken from the manual: TPE-MON 0x666a, CHAT.PROG 0xd0b3.</li>
 * <li>5ERET: ERRETURN exit. Decrements LINK, stores the error code in the caller's frame and
 *     goes on into 5LEAV, so it lands on the error slot (TPE-MON 0x6664, CHAT.PROG 0xd0ad).</li>
 * <li>Only the routine whose OWN code makes the frame jump is named: a routine that calls 5LEAV
 *     leaves through the frame as well (CHAT.PROG 0xa541), and is not the runtime.</li>
 * <li>The error slot: the word right after a call to a PLANC routine. 5LEAV skips it; 5ERET
 *     lands on it, and it holds a jump to the caller's ROUTINEERROR code or another 5ERET.</li>
 * </ul>
 *
 * <p>Lessons taken over from the MC68000 PLANC scripts (NDInsight tools/ghidra-planc): every
 * comment written here carries {@link #MARK}, so a later run may replace its OWN text but never
 * a comment a person wrote; names are given with SourceType.ANALYSIS and never replace a name a
 * person gave; and this runs after the flow fixes, because Ghidra does not recompute a function
 * body that already exists.</p>
 */
final class ND100PlancMarks {

	/** In every comment written here, so a re-run can tell its own text from a person's. */
	static final String MARK = "[nd100-planc]";

	/** LINK: the return address, at B-128 (octal -200). ND-60.117.5 page 291. */
	private static final String LINK_PLUS_0 = "-128+0";
	private static final String LINK_MINUS_1 = "-128+-1";

	/** The five inline words after JPL I (5INIT), in order (ND-60.117.5 page 292). */
	private static final String[] INIT_WORDS = {
		"stack space requirement",
		"stack array address",
		"entire stack array size in words",
		"two bank flag",
		"unused (0)",
	};

	private ND100PlancMarks() {
	}

	/**
	 * Marks the whole program, from the calls in the listing as it is now. Run once when
	 * analysis has ended: names and comments go on last, when the flow is final (lesson from
	 * the 68000 PLANC scripts - Ghidra does not recompute an existing body, and comments written
	 * during the passes were lost when a later pass cleared code).
	 */
	static void applyAll(Program program, ND100ReturnTracker t) {
		Map<Long, ND100ReturnTracker.Summary> seen = new java.util.HashMap<>();
		List<long[]> calls = new java.util.ArrayList<>();
		ghidra.program.model.listing.InstructionIterator it =
			program.getListing().getInstructions(true);
		while (it.hasNext()) {
			ghidra.program.model.listing.Instruction ins = it.next();
			if (!ins.getFlowType().isCall()) {
				continue;
			}
			long target = t.callTarget(ins);
			if (target < 0) {
				continue;
			}
			seen.computeIfAbsent(target, t::summarize);
			calls.add(new long[] { ND100ReturnTracker.word(ins.getAddress()), target });
		}
		apply(program, t, seen, calls);
	}

	/**
	 * @param seen  every call target summarised in this pass, with its summary
	 * @param calls word address of each call instruction and of its target, in pairs
	 */
	static void apply(Program program, ND100ReturnTracker t, Map<Long, ND100ReturnTracker.Summary> seen,
			List<long[]> calls) {
		int named = 0;
		// 5LEAV is named only as the routine a 5ERET runs on into. A jump through LINK alone is
		// not enough: CHAT.PROG's ON ROUTINEERROR entries (0x76b4, 0x78d0: COPY SL DX; STX ,B;
		// STA ERRCODE; LEAVE) leave through LINK with the hardware LEAVE instruction and are not
		// the runtime. In both runtimes measured, 5ERET goes straight on into 5LEAV
		// (TPE-MON 0x6664 -> 0x666a, CHAT.PROG 0xd0ad -> 0xd0b3).
		java.util.List<Long> erets = new java.util.ArrayList<>();
		java.util.List<Long> leavs = new java.util.ArrayList<>();
		for (Map.Entry<Long, ND100ReturnTracker.Summary> e : seen.entrySet()) {
			String name = runtimeName(e.getValue());
			if ("5ERET".equals(name)) {
				erets.add(e.getKey());
			}
			else if ("5LEAV".equals(name)) {
				leavs.add(e.getKey());
			}
			else if (name != null && name(program, t.wordAddr(e.getKey()), name, plate(name)
				+ (e.getValue().isUsable() ? "" : "\nNot every path was followed ("
					+ e.getValue().why + "); named from the path that builds the frame."))) {
				named++;
			}
		}
		for (int i = 0; i < erets.size(); i++) {
			for (int j = 0; j < leavs.size(); j++) {
				if (runsInto(program, t.wordAddr(erets.get(i)), t.wordAddr(leavs.get(j)))) {
					if (name(program, t.wordAddr(erets.get(i)), "5ERET", plate("5ERET"))) {
						named++;
					}
					if (name(program, t.wordAddr(leavs.get(j)), "5LEAV", plate("5LEAV"))) {
						named++;
					}
				}
			}
		}
		int sizeWords = 0;
		int slots = 0;
		for (int i = 0; i < calls.size(); i++) {
			long callWord = calls.get(i)[0];
			long target = calls.get(i)[1];
			ND100ReturnTracker.Summary s = seen.get(target);
			if (s == null) {
				continue;
			}
			Address after = t.wordAddr(callWord + 1);
			String name = runtimeName(s);
			if (!s.isUsable() && !"5ENTR".equals(name) && !"5INIT".equals(name)) {
				continue;
			}
			if ("5ENTR".equals(name)) {
				if (skipsTo(program, t.wordAddr(callWord), t.wordAddr(callWord + 2))
					&& inlineWord(program, after, "stack space requirement (inline word of 5ENTR)")) {
					sizeWords++;
				}
			}
			else if ("5INIT".equals(name)) {
				if (!skipsTo(program, t.wordAddr(callWord), t.wordAddr(callWord + 1 + INIT_WORDS.length))) {
					continue;
				}
				for (int k = 0; k < INIT_WORDS.length; k++) {
					if (inlineWord(program, t.wordAddr(callWord + 1 + k),
						INIT_WORDS[k] + " (inline word " + (k + 1) + " of 5INIT)")) {
						sizeWords++;
					}
				}
			}
			else if (s.returns.contains(0) && s.returns.contains(1)
					&& t.plancEntryCall(target) >= 0) {
				// The callee starts the PLANC way and was followed to both exits.
				if (comment(program, after, CommentType.EOL, "error slot: reached only when "
					+ t.wordAddr(target) + " ERRETURNs (5ERET); a normal return (5LEAV) skips it")) {
					slots++;
				}
			}
		}
		if (named + sizeWords + slots > 0) {
			Msg.info(ND100PlancMarks.class, "ND-100 PLANC: " + named + " runtime routines named, "
				+ sizeWords + " inline words marked, " + slots + " error slots commented");
		}
	}

	/** The PLANC runtime routine this summary describes, or null. */
	static String runtimeName(ND100ReturnTracker.Summary s) {
		// The entry routine is named even when one of its paths could not be followed (TPE-MON's
		// 0x6650: the stack overflow path ends in a jump the tracker cannot place). plancEntry is
		// only set by a path that was followed to its return and built the new frame exactly.
		if (s.plancEntry && s.returns.size() == 1) {
			int k = s.returns.first();
			return k == 1 ? "5ENTR" : k == 5 ? "5INIT" : null;
		}
		if (!s.isUsable()) {
			return null;
		}
		if (s.leavesThroughFrame && s.returns.isEmpty() && s.frameExits.size() == 1) {
			String x = s.frameExits.first();
			return LINK_PLUS_0.equals(x) ? "5LEAV" : LINK_MINUS_1.equals(x) ? "5ERET" : null;
		}
		return null;
	}

	/**
	 * True if the straight code from {@code from} reaches {@code to} within 16 instructions,
	 * following fall-throughs and forward conditional jumps in the listing.
	 */
	private static boolean runsInto(Program program, Address from, Address to) {
		Listing listing = program.getListing();
		java.util.ArrayDeque<Address> work = new java.util.ArrayDeque<>();
		java.util.Set<Address> done = new java.util.HashSet<>();
		work.add(from);
		while (!work.isEmpty() && done.size() < 16) {
			Address a = work.poll();
			if (a.equals(to)) {
				return true;
			}
			if (!done.add(a)) {
				continue;
			}
			ghidra.program.model.listing.Instruction ins = listing.getInstructionAt(a);
			if (ins == null) {
				continue;
			}
			if (ins.getFallThrough() != null) {
				work.add(ins.getFallThrough());
			}
			if (ins.getFlowType().isConditional() && ins.getFlowType().isJump()) {
				Address[] f = ins.getFlows();
				for (int i = 0; i < f.length; i++) {
					if (f[i].compareTo(a) > 0) {
						work.add(f[i]);
					}
				}
			}
		}
		return false;
	}

	private static String plate(String name) {
		switch (name) {
			case "5ENTR":
				return "PLANC runtime 5ENTR: routine entry. Builds the new stack frame at the caller's "
					+ "FREES cell + 128, saves the return address (LINK, B-128) and the old B "
					+ "(PREVB, B-127), checks for stack overflow, and returns past the one inline "
					+ "word (stack space requirement).";
			case "5INIT":
				return "PLANC runtime 5INIT: entry of a main program or a routine with INISTACK. "
					+ "Like 5ENTR but sets up a new stack; returns past five inline words.";
			case "5LEAV":
				return "PLANC runtime 5LEAV: normal exit (RETURN / ENDROUTINE). Restores B from PREVB and "
					+ "jumps to LINK, which holds the word after the error slot of the caller's call.";
			case "5ERET":
				return "PLANC runtime 5ERET: ERRETURN exit. Decrements LINK, stores the "
					+ "error code in the caller's frame (ERRCODE) and goes on into 5LEAV, so it lands on "
					+ "the error slot after the caller's call.";
			default:
				return null;
		}
	}

	/**
	 * Names the routine at {@code a}, unless a person already named it. Recognised by what it
	 * does, so the plate says so.
	 */
	private static boolean name(Program program, Address a, String name, String plate) {
		try {
			Function f = program.getFunctionManager().getFunctionAt(a);
			Symbol sym = f != null ? f.getSymbol() : program.getSymbolTable().getPrimarySymbol(a);
			if (sym != null && sym.getSource() == SourceType.USER_DEFINED) {
				return false;
			}
			if (sym != null && name.equals(sym.getName())) {
				return false;
			}
			if (f != null) {
				f.setName(name, SourceType.ANALYSIS);
			}
			else {
				program.getSymbolTable().createLabel(a, name, SourceType.ANALYSIS).setPrimary();
			}
			comment(program, a, CommentType.PLATE, plate + "\nRecognised by what the code does "
				+ "(ND-100 return tracker), not by its address. ND-60.117.5 pages 291-294.");
			return true;
		}
		catch (Exception e) {
			Msg.warn(ND100PlancMarks.class, "ND-100 PLANC: could not name " + a + " " + name + ": "
				+ e.getMessage());
			return false;
		}
	}

	/** True if the call at {@code call} has its fall-through set to {@code to} (the tracker's fix). */
	private static boolean skipsTo(Program program, Address call, Address to) {
		ghidra.program.model.listing.Instruction ins = program.getListing().getInstructionAt(call);
		return ins != null && to.equals(ins.getFallThrough());
	}

	/**
	 * Marks an inline word after an entry call as a data word with what it holds. The caller
	 * has checked that the call's fall-through skips it. If an instruction still sits on it
	 * (disassembled before the call was fixed, TPE-MON 0x2e6e), it is cleared only when it
	 * covers just that word and nothing refers to it - otherwise it is left as it is.
	 */
	private static boolean inlineWord(Program program, Address a, String what) {
		Listing listing = program.getListing();
		ghidra.program.model.listing.Instruction ins = listing.getInstructionContaining(a);
		if (ins != null) {
			if (!ins.getAddress().equals(a) || ins.getLength() != 2) {
				return false;
			}
			// References from the word itself do not count (decoded as STZ *0x2e6e, it
			// "writes" itself).
			ghidra.program.model.symbol.ReferenceIterator refs =
				program.getReferenceManager().getReferencesTo(a);
			while (refs.hasNext()) {
				if (!refs.next().getFromAddress().equals(a)) {
					return false;
				}
			}
			listing.clearCodeUnits(a, a, false);
		}
		try {
			if (listing.getDefinedDataAt(a) == null) {
				listing.clearCodeUnits(a, a, false);
				listing.createData(a, WordDataType.dataType);
			}
		}
		catch (Exception e) {
			return false;
		}
		return comment(program, a, CommentType.EOL, what);
	}

	/**
	 * Writes {@code text} (with {@link #MARK}) unless the place holds a comment a person wrote.
	 * Our own earlier text is replaced, so a corrected comment reaches the listing.
	 */
	private static boolean comment(Program program, Address a, CommentType type, String text) {
		CodeUnit cu = program.getListing().getCodeUnitAt(a);
		if (cu == null) {
			return false;
		}
		String old = cu.getComment(type);
		String now = MARK + " " + text;
		if (old != null && (!old.contains(MARK) || old.equals(now))) {
			return false;
		}
		cu.setComment(type, now);
		return true;
	}
}
