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

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Analyzer that resolves ND-100 indirect P-relative memory references.
 *
 * For instructions using addressing mode 2 (I without ,B or ,X), the pointer
 * address is P-relative and resolved at disassembly time. This analyzer reads
 * the word at that pointer address from loaded memory and adds a reference to
 * the final target address, plus an EOL comment showing the resolved target.
 *
 * For JMP/JPL indirect: defines the pointer as a code pointer and adds
 * COMPUTED_JUMP/COMPUTED_CALL references so the decompiler resolves the target.
 *
 * Also handles mode 6 (,X I *addr) where the pointer is P-relative but the
 * final address is X-indexed (target from pointer + X at runtime, but the
 * pointer dereference can still be resolved statically).
 */
public class ND100IndirectRefAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "ND-100 Indirect Reference Resolver";
	private static final String DESCRIPTION =
		"Resolves indirect P-relative references by reading pointer values from memory " +
		"and adding references to the final target addresses.";

	public ND100IndirectRefAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setDefaultEnablement(true);
		// Run after basic reference analysis so we can find existing refs
		setPriority(AnalysisPriority.REFERENCE_ANALYSIS.after());
		// Lets it be re-run on an already analysed program from
		// Analysis -> One Shot -> ND-100 Indirect Reference Resolver.
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {
		String langId = program.getLanguageID().getIdAsString();
		return langId.startsWith("ND-100:");
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		Listing listing = program.getListing();
		Memory memory = program.getMemory();
		ReferenceManager refMgr = program.getReferenceManager();
		SymbolTable symTable = program.getSymbolTable();

		InstructionIterator instrIter = listing.getInstructions(set, true);

		while (instrIter.hasNext()) {
			monitor.checkCancelled();
			Instruction instr = instrIter.next();

			// Look for "I *", which marks indirect P-relative addressing
			// (mode 2: "I *addr", mode 6: ",X I *addr"), in the WHOLE instruction text.
			//
			// Checking only getDefaultOperandRepresentation() missed JMP and JPL: their
			// constructors in nd100.slaspec write the "I *" as literal text in the
			// instruction's own display (:JMP "I *"^reloc), and Ghidra keeps such text as
			// a separator BETWEEN operands, not inside one. Only instructions that get the
			// "I *" from a shared operand subtable (addr: "I *"^reloc, e.g. LDA) had it
			// inside an operand. So every indirect JMP/JPL was skipped and its pointer
			// word stayed undefined2. Instruction.toString() joins mnemonic, separators
			// and operands in listing order, so it sees both forms.
			boolean hasIndirectPRelative = instr.toString().contains("I *");

			if (!hasIndirectPRelative) {
				continue;
			}

			// Find the pointer address from existing references.
			// SLEIGH creates a reference to the P-relative pointer location.
			Address ptrAddr = null;
			Reference[] refs = instr.getReferencesFrom();
			for (int i = 0; i < refs.length; i++) {
				Address toAddr = refs[i].getToAddress();
				// The pointer address should be in RAM near the instruction
				if (toAddr.getAddressSpace().equals(instr.getAddress().getAddressSpace())) {
					ptrAddr = toAddr;
					break;
				}
			}

			if (ptrAddr == null) {
				continue;
			}

			// Read the 16-bit word at the pointer address (big-endian ND-100)
			try {
				short targetWord = memory.getShort(ptrAddr);
				int targetOffset = Short.toUnsignedInt(targetWord);

				// Create address in the same space as the instruction
				// Multiply by wordSize because ND-100 is word-addressed (wordsize=2)
				int wordSize = instr.getAddress().getAddressSpace().getAddressableUnitSize();
				Address targetAddr = instr.getAddress().getNewAddress((long) targetOffset * wordSize);

				// Check if target is in valid memory
				if (!memory.contains(targetAddr)) {
					continue;
				}

				// Determine reference type based on mnemonic
				String mnemonic = instr.getMnemonicString();
				RefType refType;
				if ("JMP".equals(mnemonic) || "JPL".equals(mnemonic)) {
					refType = RefType.COMPUTED_JUMP;
				} else {
					refType = RefType.INDIRECTION;
				}

				// Add a reference from the instruction to the resolved target
				boolean alreadyHasRef = false;
				for (int i = 0; i < refs.length; i++) {
					if (refs[i].getToAddress().equals(targetAddr)) {
						alreadyHasRef = true;
						break;
					}
				}

				if (!alreadyHasRef) {
					refMgr.addMemoryReference(
						instr.getAddress(), targetAddr,
						refType, SourceType.ANALYSIS, 0);
				}

				// Define the pointer location as a 2-byte (one word) pointer.
				definePointer(listing, ptrAddr, instr, log);

				// Add EOL comment showing resolved indirect target
				String existingComment = instr.getComment(CommentType.EOL);
				String targetLabel = getLabel(symTable, targetAddr);
				String comment = "[" + ptrAddr + "] -> " + targetLabel;

				if (existingComment == null || !existingComment.contains("-> ")) {
					instr.setComment(CommentType.EOL, comment);
				}
			}
			catch (MemoryAccessException e) {
				// Pointer location not readable — skip
			}
		}

		return true;
	}

	/**
	 * Makes the word at {@code ptrAddr} a 2-byte pointer.
	 *
	 * <p>Why the old check was not enough: it only created the pointer when
	 * {@code getDefinedDataAt} returned null. But Ghidra's own reference analysis runs
	 * BEFORE this analyzer and applies {@code undefined2} to every word an instruction
	 * reads (the "(R)" XREF), and an applied {@code undefined2} counts as defined data
	 * (CodeManager.getDefinedDataAt returns any stored data record). So the pointer was
	 * never created and the listing showed "undefined2 7853h" instead of a pointer.</p>
	 *
	 * <p>Rule now: nothing there, or only an undefined type (undefined, undefined1/2/4/...)
	 * - replace it with the pointer. Real data typed by a person or a loader is left
	 * alone, and that is logged.</p>
	 *
	 * <p>Pointer value: {@code PointerDataType.getAddressValue} turns the stored value into
	 * an address with {@code space.getAddress(offset, true)}, i.e. as a WORD offset, so on
	 * this word-addressed space a stored 7853h points at ram:7853 as it should.</p>
	 */
	private void definePointer(Listing listing, Address ptrAddr, Instruction instr, MessageLog log) {
		if (listing.getInstructionContaining(ptrAddr) != null) {
			// The pointer word is also decoded as an instruction (code and data overlap,
			// or the jump table sits inside code). Do not destroy the instruction.
			Msg.debug(this, "Indirect pointer at " + ptrAddr + " (used by " + instr.getAddress()
				+ ") lies inside an instruction - no pointer created");
			return;
		}

		Data existing = listing.getDataContaining(ptrAddr);
		if (existing != null && existing.isDefined()
				&& !Undefined.isUndefined(existing.getDataType())) {
			if (!(existing.getDataType() instanceof Pointer)) {
				Msg.debug(this, "Indirect pointer at " + ptrAddr + " (used by " + instr.getAddress()
					+ ") already holds " + existing.getDataType().getName() + " - left as it is");
			}
			return;
		}

		try {
			if (existing != null && existing.isDefined()) {
				// Remove the undefined2 (or similar) that reference analysis put there.
				listing.clearCodeUnits(existing.getMinAddress(), existing.getMaxAddress(), false);
			}
			listing.createData(ptrAddr, new PointerDataType(null, 2));
		}
		catch (CodeUnitInsertionException e) {
			String msg = "Could not create pointer at " + ptrAddr + " (used by "
				+ instr.getAddress() + "): " + e.getMessage();
			Msg.warn(this, msg);
			log.appendMsg(msg);
		}
	}

	private String getLabel(SymbolTable symTable, Address addr) {
		Symbol[] symbols = symTable.getSymbols(addr);
		if (symbols != null && symbols.length > 0) {
			return symbols[0].getName();
		}
		return addr.toString();
	}
}
