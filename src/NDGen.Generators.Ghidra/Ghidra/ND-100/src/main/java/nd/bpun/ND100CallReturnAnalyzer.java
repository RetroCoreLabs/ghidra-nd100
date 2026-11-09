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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.core.clear.ClearFlowAndRepairCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Fixes where ND-100 calls continue. See {@link ND100ReturnTracker} for how the real return
 * point of each called routine is worked out; this class applies it to the listing:
 *
 * <ul>
 * <li>returns to L+0 only: nothing to do, that is Ghidra's default;</li>
 * <li>returns to L+k: the call's fall-through becomes call+1+k. Each word in between is
 *     either code (when it is also a return point, like PLANC's error slot that 5ERET lands
 *     on) or data (an inline parameter, or PLANC's stack-size word after 5ENTR);</li>
 * <li>never returns: the call gets no fall-through;</li>
 * <li>anything the tracker could not work out is left alone and logged.</li>
 * </ul>
 */
public class ND100CallReturnAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "ND-100 Call Return Tracker";
	private static final String DESCRIPTION =
		"Follows each called routine's own code to find where a call really returns " +
		"(inline parameter words, PLANC 5ENTR/5LEAV/5ERET, calls that never return) and " +
		"fixes the fall-through after the call.";

	private final Map<Program, ND100ReturnTracker> trackers = new WeakHashMap<>();

	public ND100CallReturnAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.DISASSEMBLY.after());
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguageID().getIdAsString().startsWith("ND-100:");
	}

	@Override
	public void analysisEnded(Program program) {
		ND100ReturnTracker t = trackers.remove(program);
		if (t == null) {
			return;
		}
		// The PLANC names and comments go on once, when the flow is final. Written during the
		// passes, most error-slot comments were lost again when a later pass cleared and
		// re-disassembled code (TPE-MON: 508 written, 97 left, measured 2026-11-08).
		int tx = program.startTransaction("ND-100 PLANC marks");
		boolean ok = false;
		try {
			ND100PlancMarks.applyAll(program, t);
			ok = true;
		}
		finally {
			program.endTransaction(tx, ok);
		}
	}

	private ND100ReturnTracker tracker(Program program) {
		ND100ReturnTracker t = trackers.get(program);
		if (t == null) {
			t = new ND100ReturnTracker(program);
			AddressIterator it = program.getSymbolTable().getExternalEntryPointIterator();
			// A PROG has a start and a restart entry; use the first one whose start code
			// gives frame facts.
			while (it.hasNext()) {
				Address entry = it.next();
				if (t.learnFrameFacts(entry)) {
					break;
				}
			}
			trackers.put(program, t);
		}
		return t;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		ND100ReturnTracker t = tracker(program);
		Listing listing = program.getListing();

		// Collect first: changing the listing while iterating it is not safe.
		List<Instruction> calls = new ArrayList<>();
		InstructionIterator it = listing.getInstructions(set, true);
		while (it.hasNext()) {
			Instruction ins = it.next();
			if (ins.getFlowType().isCall()) {
				calls.add(ins);
			}
		}

		int fixed = 0;
		int unknown = 0;
		// Functions whose flow changed. Ghidra does not shrink a function body when a call's
		// fall-through is removed, so ASSEMBLER-500's word-0 function kept 0x0000..0x037e after
		// its call was marked "never returns" and the decompiler still timed out (2026-11-08).
		java.util.Set<Function> owners = new java.util.HashSet<>();
		// Why calls were left alone: reason -> count, and the first call that had it.
		Map<String, Integer> reasonCount = new java.util.TreeMap<>();
		Map<String, String> reasonExample = new java.util.HashMap<>();
		int i = 0;
		java.util.Set<String> jumpsDone = new java.util.HashSet<>();
		do {
		for (; i < calls.size(); i++) {
			monitor.checkCancelled();
			Instruction call = calls.get(i);
			if (listing.getInstructionAt(call.getAddress()) != call) {
				continue; // removed by an earlier fix in this pass
			}
			long target = t.callTarget(call);
			if (target < 0) {
				unknown++;
				count(reasonCount, reasonExample, "call target not known", call.getAddress() + "");
				continue;
			}
			// Ghidra makes no function at the target of a call through a pointer word
			// (JPL I *ptr). ASSEMBLER-500's start code at 0x1491, reached from word 0 that way,
			// was in no function and so never decompiled (measured 2026-11-08).
			Address entry = t.wordAddr(target);
			if (program.getFunctionManager().getFunctionAt(entry) == null) {
				// Not disassembled yet when the first pass runs: the tracker has followed it as
				// this call's target, so it is code.
				if (listing.getInstructionAt(entry) == null) {
					disassemble(program, entry, monitor, calls);
				}
				if (listing.getInstructionAt(entry) != null) {
					new CreateFunctionCmd(entry).applyTo(program, monitor);
				}
			}
			ND100ReturnTracker.Summary s = t.summarize(target);
			if (s.plancEntry) {
				plancRoutineStart(program, call, monitor);
			}
			if (!s.isUsable() || (s.returns.isEmpty() && !s.neverReturns())) {
				unknown++;
				String why = !s.isUsable() ? s.why : "no return found (recursion cut)";
				int at = why.indexOf(" at ");
				String kind = at > 0 ? why.substring(0, at) : why;
				count(reasonCount, reasonExample, kind,
					call.getAddress() + " -> " + t.wordAddr(target) + ": " + why);
				continue;
			}
			// Look the function up before apply(): clearing can remove instructions.
			Function owner = program.getFunctionManager().getFunctionContaining(call.getAddress());
			if (apply(program, call, s, t, monitor, log, calls)) {
				fixed++;
				if (owner != null) {
					owners.add(owner);
				}
			}
		}
		} while (followComputedJumps(program, t, jumpsDone, monitor, calls));
		for (Function f : owners) {
			if (!f.isDeleted()) {
				CreateFunctionCmd.fixupFunctionBody(program, f, monitor);
			}
		}
		if (fixed > 0 || unknown > 0) {
			Msg.info(this, "ND-100 call return tracker: " + fixed + " calls fixed, " + unknown
				+ " left as they were");
			for (Map.Entry<String, Integer> e : reasonCount.entrySet()) {
				Msg.info(this, "  " + e.getValue() + " x " + e.getKey() + "   e.g. "
					+ reasonExample.get(e.getKey()));
			}
		}
		return true;
	}

	/**
	 * Adds a flow reference from each jump through a register to the targets the tracker found
	 * for it, and disassembles them. Ghidra cannot follow COPY ST DP or RADD SA DP itself, so
	 * the code behind them stayed undecoded (SIMDEBUG-O:PROG start code 0x22ec, 2026-11-09).
	 * Returns true when new calls were added to {@code calls}.
	 */
	private static boolean followComputedJumps(Program program, ND100ReturnTracker t,
			java.util.Set<String> done, TaskMonitor monitor, List<Instruction> calls) {
		int before = calls.size();
		Listing listing = program.getListing();
		for (Map.Entry<Long, java.util.Set<Long>> e : t.computedJumps.entrySet()) {
			Address from = t.wordAddr(e.getKey());
			Instruction jump = listing.getInstructionAt(from);
			if (jump == null) {
				continue;
			}
			for (Long target : e.getValue()) {
				if (!done.add(e.getKey() + ">" + target)) {
					continue;
				}
				Address to = t.wordAddr(target);
				if (!program.getMemory().contains(to)) {
					continue;
				}
				jump.addOperandReference(0, to, ghidra.program.model.symbol.RefType.COMPUTED_JUMP,
					ghidra.program.model.symbol.SourceType.ANALYSIS);
				if (listing.getInstructionAt(to) == null && listing.getDefinedDataAt(to) == null) {
					disassemble(program, to, monitor, calls);
				}
			}
		}
		return calls.size() > before;
	}

	private static void count(Map<String, Integer> counts, Map<String, String> examples,
			String kind, String example) {
		// Addresses differ per call; group on the text only.
		String k = kind.replaceAll("ram:[0-9a-f]+", "*").replaceAll("[0-9a-f]{4}", "*");
		counts.merge(k, 1, Integer::sum);
		examples.putIfAbsent(k, example);
	}

	private boolean apply(Program program, Instruction call, ND100ReturnTracker.Summary s,
			ND100ReturnTracker t, TaskMonitor monitor, MessageLog log, List<Instruction> calls) {
		Listing listing = program.getListing();
		long callWord = ND100ReturnTracker.word(call.getAddress());
		long l = callWord + call.getLength() / 2;

		if (s.neverReturns()) {
			if (call.isFallThroughOverridden() && call.getFallThrough() == null
				&& call.getFlowOverride() == FlowOverride.CALL_RETURN) {
				return false;
			}
			call.setFallThrough(null);
			// The listing's fall-through is not enough: the decompiler builds its own flow from
			// the p-code and went on past the call into the data after it (ASSEMBLER-500 word
			// 0, a one-instruction function that still timed out, 2026-11-08). CALL_RETURN
			// tells both that the function ends at this call.
			call.setFlowOverride(FlowOverride.CALL_RETURN);
			// After PLANC's JPL I (5LEAV) the next word is normally the next routine's first
			// instruction, often reached only through a pointer word Ghidra did not follow;
			// clearing there wiped hundreds of real routines in CHAT.PROG (measured
			// 2026-11-07). So only a call that truly never returns gets the words after it
			// cleared (ASSEMBLER-500 puts data there).
			if (!s.leavesThroughFrame && !reachedOtherwise(program, call, t.wordAddr(l))) {
				new ClearFlowAndRepairCmd(t.wordAddr(l), true, false, true).applyTo(program, monitor);
				call = again(program, call.getAddress(), monitor, calls);
				if (call == null) {
					return false;
				}
				call.setFallThrough(null);
				call.setFlowOverride(FlowOverride.CALL_RETURN);
			}
			setNote(call, s.leavesThroughFrame
				? "returns for the caller through its frame, not here (ND-100 return tracker)"
				: "call never returns (ND-100 return tracker)");
			return true;
		}

		int kmax = s.returns.last();
		if (kmax == 0) {
			return false;
		}
		Address cont = t.wordAddr(l + kmax);
		if (call.isFallThroughOverridden() && cont.equals(call.getFallThrough())) {
			return false;
		}
		call.setFallThrough(cont);

		// The words between the call and the real continuation.
		boolean anyData = false;
		for (int j = 0; j < kmax; j++) {
			if (!s.returns.contains(j)) {
				anyData = true;
			}
		}
		if (anyData && !reachedOtherwise(program, call, t.wordAddr(l))) {
			// Remove what Ghidra decoded from the words after the call; repair keeps
			// anything that is also reached from elsewhere.
			new ClearFlowAndRepairCmd(t.wordAddr(l), true, false, true).applyTo(program, monitor);
			call = again(program, call.getAddress(), monitor, calls);
			if (call == null) {
				return false;
			}
			call.setFallThrough(cont);
		}
		for (int j = 0; j < kmax; j++) {
			Address a = t.wordAddr(l + j);
			if (s.returns.contains(j)) {
				disassemble(program, a, monitor, calls);
				// No flow reference from the call to this word: tried 2026-11-07, Ghidra then split
				// functions at it (CHAT.PROG 169 -> 147 functions, 0x685a broken up). The word
				// is still disassembled as code; it just sits outside the function body.
				continue;
			}
			if (listing.getInstructionContaining(a) != null) {
				Msg.debug(this, a + ": inline word after call " + call.getAddress()
					+ " is still decoded as code (reached from elsewhere) - left alone");
				continue;
			}
			Data d = listing.getDataAt(a);
			if (d != null && d.isDefined()) {
				continue;
			}
			try {
				listing.createData(a, new WordDataType());
			}
			catch (CodeUnitInsertionException e) {
				String msg = "Could not mark " + a + " as an inline data word: " + e.getMessage();
				Msg.warn(this, msg);
				log.appendMsg(msg);
			}
		}
		disassemble(program, cont, monitor, calls);
		setNote(call, "returns to call+" + (1 + kmax) + " " + s.returns
			+ (s.assumedPlanc ? " PLANC rule assumed" : "")
			+ (s.assumedRuntime ? " runtime rule assumed for a call to an unknown routine" : "")
			+ " (ND-100 return tracker)");
		return true;
	}

	/**
	 * True when something other than this call's own fall-through refers to {@code a}: a
	 * jump, a branch, a call or a pointer. Then the code there is reached another way and must
	 * not be cleared. Measured 2026-11-07 on CHAT.PROG: the CPU's ENTR instruction branches to
	 * the word after the error call that follows it (0x7629 ENTR, 0x762b error call that
	 * never returns, 0x762c normal path), and Ghidra's clear-and-repair removed 0x762c and
	 * 29 functions reached from it.
	 */
	private static boolean reachedOtherwise(Program program, Instruction call, Address a) {
		ReferenceIterator it = program.getReferenceManager().getReferencesTo(a);
		while (it.hasNext()) {
			Reference r = it.next();
			if (!r.getFromAddress().equals(call.getAddress())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Disassembles from {@code a} and adds the calls in the new code to {@code calls}. Code this
	 * analyzer disassembles itself is not handed back to it by Ghidra: with function creation
	 * at call targets, 23 calls in CHAT.PROG 0xcb11..0xcf04 were never looked at (2026-11-08).
	 */
	private static void disassemble(Program program, Address a, TaskMonitor monitor,
			List<Instruction> calls) {
		DisassembleCommand cmd = new DisassembleCommand(a, null, true);
		cmd.applyTo(program, monitor);
		AddressSetView got = cmd.getDisassembledAddressSet();
		if (got == null || got.isEmpty()) {
			return;
		}
		InstructionIterator it = program.getListing().getInstructions(got, true);
		while (it.hasNext()) {
			Instruction ins = it.next();
			if (ins.getFlowType().isCall()) {
				calls.add(ins);
			}
		}
	}

	/**
	 * A call to PLANC's 5ENTR / 5INIT starts a routine (ND-60.117.5 pages 291-294: "COPY SL
	 * DX; JPL I (5INIT" - save the return address in X, then enter). The routine starts at the
	 * instruction before the call when that one copies L into X (RADD SL DX, COPY SL DX),
	 * otherwise at the call. PLANC routines are mostly reached through pointer words, so
	 * Ghidra made no function for them; with the tracker off it glued each one onto the
	 * routine before it by running through that routine's 5LEAV (TPE-MON-100-B00 0x3d97, glued
	 * onto 0x3d60; measured 2026-11-08).
	 */
	private static void plancRoutineStart(Program program, Instruction call, TaskMonitor monitor) {
		Address entry = call.getAddress();
		Instruction prev = program.getListing().getInstructionBefore(entry);
		if (prev != null && prev.getMaxAddress().next().equals(entry) && copiesLtoX(program, prev)) {
			entry = prev.getAddress();
		}
		if (program.getFunctionManager().getFunctionAt(entry) == null) {
			new CreateFunctionCmd(entry).applyTo(program, monitor);
		}
	}

	/** True when {@code ins} reads register L and writes register X (and nothing jumps). */
	private static boolean copiesLtoX(Program program, Instruction ins) {
		ghidra.program.model.lang.Register l = program.getRegister("L");
		ghidra.program.model.lang.Register x = program.getRegister("X");
		if (l == null || x == null || !ins.getFlowType().isFallthrough()) {
			return false;
		}
		boolean readsL = false;
		boolean writesX = false;
		for (ghidra.program.model.pcode.PcodeOp op : ins.getPcode()) {
			for (ghidra.program.model.pcode.Varnode in : op.getInputs()) {
				if (in.isRegister() && in.getOffset() == l.getOffset()) {
					readsL = true;
				}
			}
			ghidra.program.model.pcode.Varnode out = op.getOutput();
			if (out != null && out.isRegister() && out.getOffset() == x.getOffset()) {
				writesX = true;
			}
		}
		return readsL && writesX;
	}

	/**
	 * The call at {@code at} after a clear: Ghidra's clear-and-repair follows the flow from the
	 * cleared word, and when that garbage flow leads back over the call it removes the call too
	 * (CHAT.PROG, "Object has been deleted" when the note was written, 2026-11-08). The call is
	 * known code, so it is disassembled again. Null if that fails.
	 */
	private static Instruction again(Program program, Address at, TaskMonitor monitor,
			List<Instruction> calls) {
		Instruction ins = program.getListing().getInstructionAt(at);
		if (ins == null) {
			disassemble(program, at, monitor, calls);
			ins = program.getListing().getInstructionAt(at);
		}
		return ins;
	}

	private static void setNote(Instruction call, String note) {
		String old = call.getComment(CommentType.POST);
		if (old == null || !old.contains("ND-100 return tracker")) {
			call.setComment(CommentType.POST, old == null ? note : old + "\n" + note);
		}
	}
}
