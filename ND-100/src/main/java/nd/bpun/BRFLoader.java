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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * ND-100 BRF (Binary Relocatable Format) loader for Ghidra.
 *
 * BRF is the relocatable object format produced by all ND language processors
 * (MAC, FORTRAN, COBOL, PLANC, BASIC, PASCAL, NPL, C) and consumed by the
 * ND Relocating Loader / Real Time Loader / BRF Editor.
 *
 * Primary sources:
 *   - ND-60.066.04 "ND Relocating Loader", chapter 2 (format) and chapter 3 (BRF Editor)
 *   - BRF-FILE-FORMAT.md (NDInsight repo) — spec validated byte-by-byte against
 *     real PLANC compiler output (all 348 unit checksums verify)
 *
 * Format summary (all facts below VERIFIED against real files unless noted):
 *   - Byte stream of groups: <control byte> [S-group] [P-groups...]
 *   - P-group = one 16-bit word, big-endian (MSB first)
 *   - S-group = symbol in six-bit code, right-justified, zero-padded, packed
 *     MSB-first. Each character is the LOW SIX BITS of its ASCII code
 *     ('A' = 01, '_' = 037, ' ' = 040, '5' = 065). Decode: code 01-037 ->
 *     ASCII 0100 + code (letters), code 040-077 -> ASCII as is (digits and
 *     punctuation). VERIFIED 2026-11-16 against the COSMOS X.25 C00 BRF files:
 *     this gives X25SUPV, X25STOP, X25STRT, X25LG, X25PF, X2520 (the RT
 *     program names the SINTRAN RT-LOADER lists) and the PLANC runtime
 *     names 5ENTR, 5ERET, 5LEAV. The older "ASCII - 040" rule turned every
 *     letter into punctuation. A 4-byte S-group holds 5 characters (32 bits,
 *     top 2 bits zero), a 6-byte one 7 characters (top 6 bits zero) - the
 *     manual's "one to seven characters" is the 6-byte case.
 *     4 bytes by default, 6 bytes after LONGF
 *   - A unit runs BEG (017) ... END (021) <checksum>; the checksum word is the
 *     two's complement (negation) of the 16-bit sum of everything from BEG
 *     through the END byte, i.e. the whole unit INCLUDING the checksum word
 *     sums to 0 (mod 2^16). Verified byte-by-byte against real ND BRF output
 *     (e.g. ADV-EXIT.BRF: sum-through-END 0x20EE + stored 0xDF12 = 0x0000)
 *   - LONGF (032) is per-unit: every BEG resets S-groups back to 4 bytes
 *   - Zero bytes (FEED) pad between units; a single EOF (023) byte ends the file
 *
 * This loader emulates the ND Relocating Loader: it loads every unit
 * consecutively from a base address (default 0), applies all relocations and
 * fix-ups, resolves ENTR/REF symbol linkage, and emits the resulting memory
 * image plus one Ghidra label per ENTR/MAIN symbol.
 *
 * Differences from the real loader (deliberate, for static analysis):
 *   - Library units (LIBR) are ALWAYS loaded, not conditionally — we want to
 *     see all code, not just what one particular main program pulls in.
 *   - Two-bank mode (PMO/DMO/LRP/LRD) is loaded into the single default space;
 *     a warning is logged if those control numbers occur.
 *
 * REF semantics (ND-60.066.04 only says the symbol "is referenced in CLC"; it
 * does not state whether CLC advances): empirically established against
 * encos-err-i-b01.brf that REF stores its reference-chain link word AT (CLC)
 * and advances CLC by one. Re-measured 2026-11-16 with the corrected base
 * (PB = CLC-at-BEG - 1, see the BEG handler) over 4701 fix-ups in five files
 * (encos-err-i-b01 and four COSMOS X.25 C00 files): with REF taking a word,
 * every fix-up target is an already-loaded word; without it, 985 targets are
 * words never loaded. A fix-up CAN legally land on a REF word: in
 * NK-100-1BANK-C03.BRF, AIL0 is defined at 000107 and the REF at 001010 is
 * followed by AFR adding 026, i.e. "AIL0 + 026". So REF follows the manual's
 * chain mechanism exactly (section 2.5, see the REF handler): a defined
 * symbol is stored at once, an undefined one is chained and the chain is
 * walked and patched the moment the symbol is defined.
 *
 * COMMON blocks follow the 1-bank rule (ND-60.066.04 section 2.6): allocated
 * downward from the upper bound 0177777; the first ASF for a block fixes its
 * address and length.
 */
public class BRFLoader extends AbstractProgramWrapperLoader {

	public static final String BRF_NAME = "ND-100 BRF (Binary Relocatable Format)";

	// Control numbers (octal, per ND-60.066.04 section 2.9)
	private static final int C_FEED  = 000;  // neglect / padding
	private static final int C_LF    = 001;  // load word
	private static final int C_LR    = 002;  // load relocated (W1+PB)
	private static final int C_LC    = 003;  // load COMMON-relative (W1+CDB)
	private static final int C_AFF   = 004;  // fixup W1+(W2)->(W2)
	private static final int C_ARF   = 005;  // fixup W1+PB+(W2)->(W2)
	private static final int C_AFR   = 006;  // fixup W1+(W2+PB)->(W2+PB)
	private static final int C_ARR   = 007;  // fixup W1+PB+(W2+PB)->(W2+PB)
	private static final int C_SFL   = 010;  // set load address
	private static final int C_AFL   = 011;  // advance load address, fill zeros
	private static final int C_SRL   = 012;  // set relative load address (PB+W1)
	private static final int C_MAIN  = 014;  // symbolic start address
	private static final int C_LIBR  = 015;  // library entry point (conditional load)
	private static final int C_ENTR  = 016;  // symbol := CLC
	private static final int C_BEG   = 017;  // begin unit, PB := CLC
	private static final int C_REF   = 020;  // external reference at CLC (consumes 1 word — see class doc)
	private static final int C_END   = 021;  // end unit, W1 = checksum
	private static final int C_INHB  = 022;  // compilation errors occurred
	private static final int C_EOF   = 023;  // end of loading
	private static final int C_LNF   = 024;  // load N words fast
	private static final int C_RT    = 025;  // real-time priority
	private static final int C_ASF   = 026;  // allocate COMMON block
	private static final int C_ADS   = 027;  // add COMMON address to (CLC-1)
	private static final int C_ID30  = 030;  // "not used" per manual; observed as PLANC id stamp (count + ASCII words)
	private static final int C_LONGF = 032;  // 6-byte S-groups for the rest of this unit
	private static final int C_INL   = 034;  // W2 -> (W1+PB)
	private static final int C_DBL   = 035;  // 2 words -> (W1+PB..)
	private static final int C_RLL   = 036;  // 3 words -> (W1+PB..)
	private static final int C_CXL   = 037;  // 6 words -> (W1+PB..)
	private static final int C_INC   = 040;  // 1 word  -> (W4+ADR) in COMMON
	private static final int C_DBC   = 041;  // 2 words -> (W4+ADR..)
	private static final int C_RLC   = 042;  // 3 words -> (W4+ADR..)
	private static final int C_CXC   = 043;  // 6 words -> (W4+ADR..)
	private static final int C_BYL   = 044;  // byte load into (W1+PB)
	private static final int C_BYC   = 045;  // byte load into (W4+ADR) in COMMON
	private static final int C_NWL   = 046;  // line number (not in use)
	private static final int C_DBG   = 047;  // debug mode on/off
	private static final int C_PMO   = 050;  // program bank mode
	private static final int C_DMO   = 051;  // data bank mode
	private static final int C_LRP   = 052;  // LR with program-bank PB
	private static final int C_LRD   = 053;  // LR with data-bank PB
	private static final int C_DIC   = 054;  // dictionary table, terminated by 177777

	private static final int WORD_MASK   = 0xFFFF;
	private static final int MEM_WORDS   = 0x10000;   // full 16-bit word address space
	private static final int END_OF_LIST = 0177777;   // REF chain terminator / DIC terminator

	/** One defined or referenced symbol. */
	private static class BrfSymbol {
		String name;
		boolean defined;
		int value;          // 16-bit address when defined
		int space;          // image space the value lies in (see BrfImage)
		int definedInUnit;  // 1-based unit number of the defining ENTR/ASF
		boolean isCommon;   // defined via ASF (value = block start, length below)
		int commonLength;
		List<Integer> refLocations = new ArrayList<>();  // every REF word (image location), for annotation
		// Head of the reference chain per image space: the last REF word in that
		// space still waiting for the value. Its word holds the 16-bit address of
		// the previous REF word of the same symbol in the same space, the first
		// holds 0177777 (ND-60.066.04 section 2.5). One chain per space is this
		// loader's choice: the manual describes one 64K address space; how the
		// real loader chains references across the program and data bank is not
		// documented.
		Map<Integer, Integer> chainHeads = new LinkedHashMap<>();
	}

	/** Per-unit info collected for annotation. */
	private static class UnitInfo {
		int number;              // 1-based, as the BRF Editor numbers them
		long fileOffset;         // offset of the BEG byte
		int pb;                  // address of the unit's first program word (CLC at BEG); the loader's base is pb - 1
		int space;               // image space of the program part
		int endClc;              // program CLC after the unit
		int dataPb = -1;         // first data-bank word (two-bank units), -1 = no data bank yet
		int dataSpace = -1;
		int dataEnd = -1;
		boolean longf;
		boolean checksumOk;
		int checksumStored;      // checksum P-group after END
		int checksumComputed;    // our running sum from BEG through END
		int rtPriority = -1;     // RT group value, -1 = none
		boolean inhibit;         // INHB seen: compilation errors
		List<String> libr = new ArrayList<>();
		List<String> entr = new ArrayList<>();
		String main;             // MAIN symbol, if any
		int mainLoc = -1;        // image location of the MAIN start (CLC at the MAIN group)
		String idStamp;          // control-30 ASCII payload (PLANC id), if any
	}

	/**
	 * Result of interpreting the whole BRF stream.
	 *
	 * The image is a list of 64K-word SPACES. Space 0 is the program space
	 * (Ghidra's default "ram" space). More spaces are made when needed:
	 *  - "BRF_DATA": the data bank of a two-bank program (PMO/DMO groups,
	 *    ND-60.066.04 sections 2.6 and 2.9). Shown in Ghidra as an overlay of
	 *    ram: same addresses, separate memory.
	 *  - "BRF_PAGE2", "BRF_PAGE3", ...: when the next unit no longer fits below
	 *    0200000 in the current program (or data) space. The real loader never
	 *    meets this, because it loads a library unit only when a symbol of it is
	 *    referenced (LIBR, section 2.4); this loader loads every unit so all code
	 *    can be read, and a big library (X25-UTILITY-C00: 761 units, 0x1321A
	 *    words; TCP-ERROR-1-B05: 0x24881 words) does not fit in one 64K space.
	 *    A unit is never split across spaces.
	 * An image location is (space << 16) | 16-bit word address.
	 */
	private static class BrfImage {
		List<int[]> words = new ArrayList<>();
		List<boolean[]> defined = new ArrayList<>();   // word was written by the BRF
		List<boolean[]> reserved = new ArrayList<>();  // COMMON area: allocated, never written
		List<String> spaceNames = new ArrayList<>();
		List<Boolean> spaceIsData = new ArrayList<>();
		Map<String, BrfSymbol> symbols = new LinkedHashMap<>();
		List<UnitInfo> units = new ArrayList<>();
		int commonTop = 0177777; // 1-bank COMMON allocation grows downward from here (space 0)
		boolean twoBank;         // the file has PMO/DMO groups (found by the pre-scan)
		boolean sawEof;
		int checksumFailures;

		BrfImage() {
			newSpace("ram", false);
		}

		int newSpace(String name, boolean data) {
			words.add(new int[MEM_WORDS]);
			defined.add(new boolean[MEM_WORDS]);
			reserved.add(new boolean[MEM_WORDS]);
			spaceNames.add(name);
			spaceIsData.add(data);
			return words.size() - 1;
		}

		int read(int loc) {
			return words.get(loc >>> 16)[loc & WORD_MASK];
		}

		boolean isDefined(int loc) {
			return defined.get(loc >>> 16)[loc & WORD_MASK];
		}
	}

	/** Image location of a 16-bit word address in a space. */
	private static int loc(int space, int addr) {
		return (space << 16) | (addr & WORD_MASK);
	}

	@Override
	public String getName() {
		return BRF_NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		if (!probeBrf(provider)) {
			return List.of();
		}
		LanguageCompilerSpecPair lcs = new LanguageCompilerSpecPair("ND-100:BE:16:default", "default");
		return List.of(new LoadSpec(this, 0, lcs, true));
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.SPECIALIZED_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 50;
	}

	// -----------------------------------------------------------------------
	// Detection
	// -----------------------------------------------------------------------

	/**
	 * A BRF file starts (after optional FEED zero padding) with BEG (017),
	 * and the first unit must parse group-by-group to END with a verifying
	 * checksum. Parsing a whole unit is cheap and makes false positives on
	 * arbitrary binaries essentially impossible.
	 */
	/**
	 * Logs why the file is not a BRF file and returns false. See {@link ProbeLog}.
	 */
	private boolean reject(ByteProvider p, String reason) {
		return ProbeLog.reject(this, "BRF", p, reason, "brf");
	}

	private boolean probeBrf(ByteProvider p) throws IOException {
		long len = p.length();
		if (len < 8) {
			return reject(p, "file is only " + len + " bytes, a BRF file needs at least 8");
		}
		// Read enough for the whole first unit: a unit can be far bigger than
		// 64 KB (the check below needs it all to verify the END checksum).
		byte[] head = p.readBytes(0, Math.min(len, 4L * 1024 * 1024));
		int pos = 0;
		// Skip FEED padding, but don't accept a file that is mostly zeros:
		// require BEG within the first 4 KiB.
		while (pos < head.length && head[pos] == 0) {
			pos++;
			if (pos > 4096) {
				return reject(p, "more than 4096 zero bytes at the start, no BEG control byte found");
			}
		}
		if (pos >= head.length) {
			return reject(p, "the file is all zero bytes");
		}
		if ((head[pos] & 0xFF) != C_BEG) {
			return reject(p, String.format(
				"first non-zero byte at %d is 0x%02X, a BRF unit must start with BEG (0x%02X)",
				pos, head[pos] & 0xFF, C_BEG));
		}
		try {
			if (checkReadUnit(head, pos) > 0) {
				return true;
			}
			return reject(p, String.format(
				"the unit starting with BEG at byte %d fails the BRF syntax or END checksum check "
					+ "(only the first %d bytes are read for this check)",
				pos, head.length));
		}
		catch (IOException e) {
			return reject(p, String.format("the unit starting with BEG at byte %d could not be read: %s",
				pos, e.getMessage()));
		}
	}

	/**
	 * Syntax-check one unit starting at the BEG byte at {@code pos}; verifies
	 * the END checksum. Returns the offset just past the checksum P-group, or
	 * -1 if the unit does not verify. Mirrors the loader's "check-read" of
	 * skipped library units.
	 */
	private int checkReadUnit(byte[] buf, int pos) throws IOException {
		boolean longf = false;
		int sum = 0;
		if ((buf[pos] & 0xFF) != C_BEG) {
			return -1;
		}
		sum += C_BEG;
		pos++;
		while (true) {
			if (pos >= buf.length) {
				return -1;
			}
			int c = buf[pos++] & 0xFF;
			sum = (sum + c) & WORD_MASK;
			int sBytes = longf ? 6 : 4;
			int nPGroups;
			boolean hasSym = false;
			switch (c) {
				case C_FEED: case C_INHB: case C_DBG:
				case C_PMO: case C_DMO:
					nPGroups = 0;
					break;
				case C_LONGF:
					longf = true;
					nPGroups = 0;
					break;
				case C_LF: case C_LR: case C_LC:
				case C_SFL: case C_AFL: case C_SRL:
				case C_RT: case C_NWL: case C_LRP: case C_LRD:
					nPGroups = 1;
					break;
				case C_AFF: case C_ARF: case C_AFR: case C_ARR:
				case C_INL: case C_BYL:
					nPGroups = 2;
					break;
				case C_DBL:
					nPGroups = 3;
					break;
				case C_RLL:
					nPGroups = 4;
					break;
				case C_CXL:
					nPGroups = 7;
					break;
				case C_MAIN: case C_LIBR: case C_ENTR: case C_REF:
					hasSym = true;
					nPGroups = 0;
					break;
				case C_ASF:
					hasSym = true;
					nPGroups = 1;
					break;
				case C_ADS:
					hasSym = true;
					nPGroups = 0;
					break;
				case C_INC:
					hasSym = true;
					nPGroups = 2;
					break;
				case C_DBC:
					hasSym = true;
					nPGroups = 3;
					break;
				case C_RLC:
					hasSym = true;
					nPGroups = 4;
					break;
				case C_CXC:
					hasSym = true;
					nPGroups = 7;
					break;
				case C_BYC:
					hasSym = true;
					nPGroups = 3;
					break;
				case C_LNF: case C_ID30: {
					// count word, then count payload words
					if (pos + 2 > buf.length) {
						return -1;
					}
					int count = word(buf, pos);
					sum = (sum + count) & WORD_MASK;
					pos += 2;
					if (pos + count * 2 > buf.length) {
						return -1;
					}
					for (int i = 0; i < count; i++) {
						sum = (sum + word(buf, pos)) & WORD_MASK;
						pos += 2;
					}
					continue;
				}
				case C_DIC: {
					// 5-word elements until a 177777 terminator word
					while (true) {
						if (pos + 2 > buf.length) {
							return -1;
						}
						int w = word(buf, pos);
						sum = (sum + w) & WORD_MASK;
						pos += 2;
						if (w == END_OF_LIST) {
							break;
						}
						// remaining 4 words of the element
						if (pos + 8 > buf.length) {
							return -1;
						}
						for (int i = 0; i < 4; i++) {
							sum = (sum + word(buf, pos)) & WORD_MASK;
							pos += 2;
						}
					}
					continue;
				}
				case C_END: {
					// checksum P-group: the whole unit (BEG..END byte plus this
					// checksum word) is a two's-complement sum that comes to 0.
					if (pos + 2 > buf.length) {
						return -1;
					}
					int stored = word(buf, pos);
					pos += 2;
					if (((sum + stored) & WORD_MASK) != 0) {
						return -1;
					}
					return pos;
				}
				default:
					return -1;   // 013, 031, 033 and >054 are illegal
			}
			if (hasSym) {
				if (pos + sBytes > buf.length) {
					return -1;
				}
				for (int i = 0; i < sBytes; i += 2) {
					sum = (sum + word(buf, pos + i)) & WORD_MASK;
				}
				pos += sBytes;
			}
			for (int i = 0; i < nPGroups; i++) {
				if (pos + 2 > buf.length) {
					return -1;
				}
				sum = (sum + word(buf, pos)) & WORD_MASK;
				pos += 2;
			}
		}
	}

	// -----------------------------------------------------------------------
	// Loading
	// -----------------------------------------------------------------------

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {

		ByteProvider provider = settings.provider();
		TaskMonitor monitor   = settings.monitor();
		MessageLog log        = settings.log();

		monitor.setMessage("Loading BRF file...");

		byte[] file = provider.readBytes(0, provider.length());
		BrfImage img = interpret(file, log, monitor);

		Memory memory = program.getMemory();
		AddressSpace ram = program.getAddressFactory().getDefaultAddressSpace();
		SymbolTable symtab = program.getSymbolTable();
		Listing listing = program.getListing();

		// ND-100 is word-addressed; default-space wordSize is 2.
		int wordSize = ram.getAddressableUnitSize();

		// One Ghidra address space per image space: 0 = ram; every other image
		// space becomes ONE overlay block of ram (same addresses, separate
		// memory) covering its lowest to highest used word. Ghidra makes the
		// overlay space from the block; words inside that range the BRF never
		// loaded read as 0 there (the block comment says so).
		int nSpaces = img.words.size();
		AddressSpace[] spaces = new AddressSpace[nSpaces];
		spaces[0] = ram;
		AddressSet codeRange = new AddressSet();
		for (int s = 1; s < nSpaces; s++) {
			boolean[] def = img.defined.get(s);
			boolean[] res = img.reserved.get(s);
			int lo = -1;
			int hi = -1;
			int nLoaded = 0;
			for (int i = 0; i < MEM_WORDS; i++) {
				if (def[i] || res[i]) {
					if (lo < 0) {
						lo = i;
					}
					hi = i;
				}
				if (def[i]) {
					nLoaded++;
				}
			}
			String name = img.spaceNames.get(s);
			if (lo < 0) {
				lo = 0;
				hi = 0;
			}
			int nWords = hi - lo + 1;
			int[] w = img.words.get(s);
			byte[] data = new byte[nWords * 2];
			for (int i = 0; i < nWords; i++) {
				data[i * 2]     = (byte) ((w[lo + i] >> 8) & 0xFF);
				data[i * 2 + 1] = (byte) (w[lo + i] & 0xFF);
			}
			try {
				MemoryBlock blk = memory.createInitializedBlock(name, ram.getAddress((long) lo * wordSize),
						new ByteArrayInputStream(data), data.length, monitor, true);
				spaces[s] = blk.getStart().getAddressSpace();
				blk.setComment(String.format(
						"BRF %s: 0%06o..0%06o, %d of %d words loaded by the BRF (the rest read as 0)",
						img.spaceIsData.get(s) ? "data bank" : "program units past 64K words",
						lo, hi, nLoaded, nWords));
				blk.setRead(true);
				blk.setWrite(true);
				blk.setExecute(!img.spaceIsData.get(s));
				if (!img.spaceIsData.get(s)) {
					codeRange.add(blk.getStart(), blk.getEnd());
				}
				log.appendMsg(String.format("Overlay block %s: 0%06o..0%06o (%d words loaded)",
						name, lo, hi, nLoaded));
			}
			catch (Exception e) {
				throw new IOException("Failed to create overlay block " + name + ": " +
						e.getMessage(), e);
			}
		}

		// Space 0: one memory block per contiguous run of defined words, and one
		// uninitialized block per run of COMMON words that were allocated but
		// never written.
		Address firstBlockStart = null;
		for (int s = 0; s < 1; s++) {
			boolean[] def = img.defined.get(s);
			boolean[] res = img.reserved.get(s);
			int[] w = img.words.get(s);
			boolean isData = img.spaceIsData.get(s);
			String prefix = (s == 0) ? "BRF_" : img.spaceNames.get(s) + "_";
			int run = 0;
			while (run < MEM_WORDS) {
				if (!def[run] && !res[run]) {
					run++;
					continue;
				}
				boolean init = def[run];
				int start = run;
				while (run < MEM_WORDS && (init ? def[run] : (res[run] && !def[run]))) {
					run++;
				}
				int nWords = run - start;
				Address blockStart = spaces[s].getAddress((start & 0xFFFFL) * wordSize);
				String blockName = String.format("%s%06o", prefix, start);
				try {
					MemoryBlock blk;
					if (init) {
						byte[] data = new byte[nWords * 2];
						for (int i = 0; i < nWords; i++) {
							data[i * 2]     = (byte) ((w[start + i] >> 8) & 0xFF);
							data[i * 2 + 1] = (byte) (w[start + i] & 0xFF);
						}
						blk = memory.createInitializedBlock(blockName, blockStart,
								new ByteArrayInputStream(data), data.length, monitor, false);
						blk.setComment(String.format("BRF image (%s): 0%06o..0%06o (%d words)",
								img.spaceNames.get(s), start, run - 1, nWords));
					}
					else {
						blk = memory.createUninitializedBlock(blockName, blockStart,
								(long) nWords * 2, false);
						blk.setComment(String.format(
								"COMMON area (%s): 0%06o..0%06o (%d words), allocated by ASF, never loaded",
								img.spaceNames.get(s), start, run - 1, nWords));
					}
					blk.setRead(true);
					blk.setWrite(true);
					blk.setExecute(init && !isData);
					if (init && !isData) {
						codeRange.add(blk.getStart(), blk.getEnd());
						if (firstBlockStart == null && s == 0) {
							firstBlockStart = blockStart;
						}
					}
					log.appendMsg(String.format("Block %s: %d words at 0%06o..0%06o",
							blockName, nWords, start, run - 1));
				}
				catch (Exception e) {
					throw new IOException("Failed to create memory block " + blockName + ": " +
							e.getMessage(), e);
				}
			}
		}
		if (codeRange.isEmpty()) {
			throw new IOException("BRF file produced no loaded words");
		}
		if (firstBlockStart == null) {
			firstBlockStart = codeRange.getMinAddress();
		}

		// Labels for all defined symbols (ENTR / COMMON blocks).
		int nDefined = 0;
		int nUnresolved = 0;
		StringBuilder unresolved = new StringBuilder();
		for (BrfSymbol sym : img.symbols.values()) {
			if (sym.defined) {
				Address a = addr(spaces, wordSize, loc(sym.space, sym.value));
				try {
					symtab.createLabel(a, sanitizeLabel(sym.name), null, SourceType.IMPORTED);
					nDefined++;
				}
				catch (InvalidInputException e) {
					log.appendMsg("Warning: could not create label for symbol '" +
							sym.name + "': " + e.getMessage());
				}
				// Metadata comment at the definition site.
				String defc;
				if (sym.isCommon) {
					defc = String.format("BRF COMMON block %s: %d words at 0%06o (ASF in unit %d)",
							sym.name, sym.commonLength, sym.value, sym.definedInUnit);
				}
				else {
					defc = String.format("BRF ENTR %s = 0%06o (defined in unit %d, %d reference%s)",
							sym.name, sym.value, sym.definedInUnit,
							sym.refLocations.size(), sym.refLocations.size() == 1 ? "" : "s");
				}
				appendComment(listing, a, CommentType.PRE, defc);
			}
			else if (!sym.refLocations.isEmpty()) {
				nUnresolved++;
				if (unresolved.length() > 0) {
					unresolved.append(", ");
				}
				unresolved.append(sym.name);
			}
		}
		if (nUnresolved > 0) {
			log.appendMsg(String.format(
					"%d unresolved external symbols (reference words hold the loader's chain links; the first holds 0177777): %s",
					nUnresolved, unresolved));
		}

		// Every REF word gets:
		//  - a relocation table entry (type = BRF control number 020, value =
		//    the word as loaded: the symbol value, or the chain link when the
		//    symbol is not defined in this file), so the link shows in Ghidra's
		//    Relocation Table with the symbol name;
		//  - for a symbol no unit in this file defines: a Ghidra external
		//    symbol (shown under Imports) and an external data reference from
		//    the REF word to it. These are the names the RT-LOADER resolves
		//    from the other files of the load (another BRF, a COMMON block,
		//    or SINTRAN itself - an RT program name stands for its RT
		//    description address, ND-60.051.8 DEFINE-PROGRAM);
		//  - an EOL comment naming the symbol.
		RelocationTable relocs = program.getRelocationTable();
		ExternalManager extMgr = program.getExternalManager();
		ReferenceManager refMgr = program.getReferenceManager();
		for (BrfSymbol sym : img.symbols.values()) {
			ExternalLocation ext = null;
			if (!sym.defined && !sym.refLocations.isEmpty()) {
				try {
					ext = extMgr.addExtLocation(ghidra.program.model.listing.Library.UNKNOWN,
							sanitizeLabel(sym.name), null, SourceType.IMPORTED);
				}
				catch (Exception e) {
					log.appendMsg("Warning: could not create external symbol '" +
							sym.name + "': " + e.getMessage());
				}
			}
			for (int i = 0; i < sym.refLocations.size(); i++) {
				int l = sym.refLocations.get(i);
				Address a = addr(spaces, wordSize, l);
				int stored = img.read(l);
				relocs.add(a, sym.defined ? Relocation.Status.APPLIED : Relocation.Status.FAILURE,
						C_REF, new long[] { stored }, 2, sym.name);
				if (ext != null) {
					try {
						refMgr.addExternalReference(a, 0, ext, SourceType.IMPORTED, RefType.DATA);
					}
					catch (InvalidInputException e) {
						log.appendMsg("Warning: could not add external reference to '" +
								sym.name + "' at " + a + ": " + e.getMessage());
					}
				}
				String rc = sym.defined
						? String.format("BRF REF %s -> 0%06o", sym.name, sym.value)
						: String.format("BRF REF %s (UNRESOLVED: word is a chain link to the previous reference, 0177777 = first)", sym.name);
				appendComment(listing, a, CommentType.EOL, rc);
			}
		}

		// MAIN: the unit's start address (CLC at the MAIN group). In the
		// relocating loader it becomes the program's main entry (ND-60.066.04
		// section 2.9); the RT-LOADER makes it an RT program (IGNORE-MAIN,
		// ND-60.051.8: "the main entry ... is substituted by an entry
		// definition" when MAIN is ignored). A REF to the name is NOT this
		// address in an RT load - it is the RT description address, so a
		// referenced MAIN name also stays an import.
		AddressSet starts = new AddressSet();
		Address entryAddr = null;
		String entryDesc = "first loaded word (no MAIN group)";
		String firstMain = null;
		for (UnitInfo u : img.units) {
			if (u.mainLoc < 0) {
				continue;
			}
			Address a = addr(spaces, wordSize, u.mainLoc);
			try {
				symtab.createLabel(a, sanitizeLabel(u.main), null, SourceType.IMPORTED);
			}
			catch (InvalidInputException e) {
				log.appendMsg("Warning: could not create MAIN label '" + u.main + "': " + e.getMessage());
			}
			appendComment(listing, a, CommentType.PRE, String.format(
					"BRF MAIN %s: start address 0%06o (unit %d)", u.main, u.mainLoc & WORD_MASK, u.number));
			symtab.addExternalEntryPoint(a);
			starts.add(a);
			if (entryAddr == null) {
				entryAddr = a;
				firstMain = u.main;
				entryDesc = "MAIN " + u.main;
			}
		}
		if (entryAddr == null) {
			entryAddr = firstBlockStart;
			symtab.addExternalEntryPoint(entryAddr);
			starts.add(entryAddr);
		}
		try {
			symtab.createLabel(entryAddr, "START", null, SourceType.IMPORTED);
		}
		catch (InvalidInputException e) {
			log.appendMsg("Warning: could not create START label: " + e.getMessage());
		}
		log.appendMsg("Entry point: " + entryAddr + " (" + entryDesc + ")");

		// Per-unit annotation: plate comment with all unit metadata at the
		// unit's program base.
		for (UnitInfo u : img.units) {
			Address a = addr(spaces, wordSize, loc(u.space, u.pb));
			StringBuilder c = new StringBuilder();
			c.append(String.format("=== BRF unit %d ===\n", u.number));
			c.append(String.format("File offset: 0x%X\n", u.fileOffset));
			c.append(String.format("Program part: first word 0%06o in %s, end CLC: 0%06o (%d words)\n",
					u.pb, img.spaceNames.get(u.space), u.endClc, (u.endClc - u.pb) & WORD_MASK));
			if (u.dataSpace >= 0) {
				c.append(String.format("Data part: first word 0%06o in %s, end CLC: 0%06o (%d words)\n",
						u.dataPb, img.spaceNames.get(u.dataSpace), u.dataEnd,
						(u.dataEnd - u.dataPb) & WORD_MASK));
			}
			c.append(String.format("S-groups: %s\n", u.longf ? "6-byte (LONGF)" : "4-byte"));
			c.append(String.format("Checksum: stored 0%06o, computed sum 0%06o [%s]",
					u.checksumStored, u.checksumComputed, u.checksumOk ? "OK" : "MISMATCH"));
			if (u.rtPriority >= 0) {
				c.append(String.format("\nReal-time priority (RT): 0%o", u.rtPriority));
			}
			if (u.inhibit) {
				c.append("\nINHB: compiler reported errors in this unit");
			}
			if (u.main != null) {
				c.append("\nMAIN: ").append(u.main);
			}
			if (!u.libr.isEmpty()) {
				c.append("\nLIBR: ").append(String.join(", ", u.libr));
			}
			if (!u.entr.isEmpty()) {
				c.append("\nENTR: ").append(String.join(", ", u.entr));
			}
			if (u.idStamp != null) {
				c.append("\nID stamp (ctrl 30): ").append(u.idStamp);
			}
			// Units can share a PB (empty units); append rather than overwrite.
			appendComment(listing, a, CommentType.PLATE, c.toString());
		}

		// File-level header plate comment at the entry with all file metadata.
		int nLongf = 0;
		int nLibrUnits = 0;
		for (UnitInfo u : img.units) {
			if (u.longf) {
				nLongf++;
			}
			if (!u.libr.isEmpty()) {
				nLibrUnits++;
			}
		}
		StringBuilder meta = new StringBuilder();
		meta.append("=== BRF file header ===\n");
		meta.append(String.format("File: %s (%d bytes)\n", provider.getName(), provider.length()));
		meta.append(String.format("Units: %d (%d LONGF / %d short S-group, %d library units)\n",
				img.units.size(), nLongf, img.units.size() - nLongf, nLibrUnits));
		meta.append(String.format("Symbols: %d defined, %d unresolved external\n",
				nDefined, nUnresolved));
		if (nUnresolved > 0) {
			meta.append("Unresolved: ").append(unresolved).append('\n');
		}
		meta.append(String.format("Entry: %s\n", entryDesc));
		if (firstMain != null) {
			meta.append(String.format("First MAIN: %s\n", firstMain));
		}
		if (img.commonTop != 0177777) {
			meta.append(String.format("COMMON allocated: 0%06o..0177777 (downward, 1-bank rule)\n",
					(img.commonTop + 1) & WORD_MASK));
		}
		meta.append(String.format("Checksums: %d of %d units OK\n",
				img.units.size() - img.checksumFailures, img.units.size()));
		if (img.checksumFailures > 0) {
			meta.append(String.format("WARNING: %d unit checksum failures\n", img.checksumFailures));
		}
		if (img.twoBank) {
			meta.append("Two-bank program: the data bank (DMO groups) is in overlay space BRF_DATA. " +
					"Its first address 0 is this loader's choice; the real address is set at load time.\n");
		}
		for (int s = 1; s < nSpaces; s++) {
			if (img.spaceNames.get(s).contains("PAGE")) {
				meta.append(String.format("Units that did not fit in 64K words continue in overlay space %s\n",
						img.spaceNames.get(s)));
			}
		}
		if (!img.sawEof) {
			meta.append("Note: no EOF (023) terminator found\n");
		}
		appendComment(listing, entryAddr, CommentType.PLATE, meta.toString());

		log.appendMsg(String.format("BRF: %d units, %d defined symbols, %d checksum failures",
				img.units.size(), nDefined, img.checksumFailures));

		// Disassemble from the entry point and every MAIN start, following flow
		// through the program-space blocks (never into the data bank).
		DisassembleCommand cmd = new DisassembleCommand(starts, codeRange, true);
		cmd.applyTo(program, monitor);

		monitor.setMessage("BRF loading complete");
	}

	/** Ghidra address of an image location. */
	private static Address addr(AddressSpace[] spaces, int wordSize, int l) {
		return spaces[l >>> 16].getAddress(((long) (l & WORD_MASK)) * wordSize);
	}

	// -----------------------------------------------------------------------
	// BRF interpretation (emulated relocating loader)
	// -----------------------------------------------------------------------

	/** What the pre-scan of one unit found (see {@link #scanUnit}). */
	private static class UnitScan {
		int[] extent = new int[2];  // words the unit needs from its first word, per bank (0 = program, 1 = data)
		boolean absolute;           // SFL seen: the unit sets an absolute load address
		boolean twoBank;            // PMO/DMO seen
	}

	/**
	 * Walk one unit's groups (from its BEG byte) and work out how many words
	 * it occupies in each bank, without loading anything. Used to start a unit
	 * in a fresh 64K space instead of letting it wrap past 0177777. The CLC
	 * rules are the interpreter's: LF/LR/LC/LRP/LRD/REF take one word, LNF
	 * takes its count, AFL advances, SRL sets CLC relative to the base
	 * (first word - 1), INL/DBL/RLL/CXL/BYL write at base + W1.
	 */
	private static UnitScan scanUnit(byte[] buf, int pos) throws IOException {
		UnitScan sc = new UnitScan();
		int[] rc = new int[2];      // CLC relative to the unit's first word, per bank
		int cur = 0;
		boolean longf = false;
		pos++;                      // the BEG byte
		while (pos < buf.length) {
			int c = buf[pos++] & 0xFF;
			int sBytes = longf ? 6 : 4;
			switch (c) {
				case C_FEED: case C_INHB: case C_DBG:
					break;
				case C_LONGF:
					longf = true;
					break;
				case C_PMO:
					cur = 0;
					sc.twoBank = true;
					break;
				case C_DMO:
					cur = 1;
					sc.twoBank = true;
					break;
				case C_LF: case C_LR: case C_LC: case C_LRP: case C_LRD:
					pos += 2;
					rc[cur]++;
					break;
				case C_AFF: case C_ARF: case C_AFR: case C_ARR:
					pos += 4;
					break;
				case C_SFL:
					pos += 2;
					sc.absolute = true;
					break;
				case C_AFL:
					rc[cur] += word(buf, pos);
					pos += 2;
					break;
				case C_SRL:
					rc[cur] = word(buf, pos) - 1;
					pos += 2;
					break;
				case C_RT: case C_NWL:
					pos += 2;
					break;
				case C_MAIN: case C_LIBR: case C_ENTR: case C_ADS:
					pos += sBytes;
					break;
				case C_REF:
					pos += sBytes;
					rc[cur]++;
					break;
				case C_ASF:
					pos += sBytes + 2;
					break;
				case C_INL: case C_BYL:
					sc.extent[cur] = Math.max(sc.extent[cur], word(buf, pos));
					pos += 4;
					break;
				case C_DBL: case C_RLL: case C_CXL: {
					int n = (c == C_DBL) ? 2 : (c == C_RLL) ? 3 : 6;
					sc.extent[cur] = Math.max(sc.extent[cur], word(buf, pos) - 1 + n);
					pos += 2 + 2 * n;
					break;
				}
				case C_INC: case C_BYC:
					pos += sBytes + 4;
					break;
				case C_DBC:
					pos += sBytes + 6;
					break;
				case C_RLC:
					pos += sBytes + 8;
					break;
				case C_CXC:
					pos += sBytes + 14;
					break;
				case C_LNF: {
					int n = word(buf, pos);
					rc[cur] += n;
					pos += 2 + 2 * n;
					break;
				}
				case C_ID30: {
					int n = word(buf, pos);
					pos += 2 + 2 * n;
					break;
				}
				case C_DIC:
					while (word(buf, pos) != END_OF_LIST) {
						pos += 10;
					}
					pos += 2;
					break;
				case C_END:
					return sc;
				default:
					// Illegal control numbers are reported by the interpreter.
					return sc;
			}
			sc.extent[cur] = Math.max(sc.extent[cur], rc[cur]);
		}
		return sc;
	}

	/** True when any unit of the file has PMO/DMO groups. */
	private static boolean fileIsTwoBank(byte[] buf) throws IOException {
		int pos = 0;
		while (pos < buf.length) {
			int c = buf[pos] & 0xFF;
			if (c == C_FEED) {
				pos++;
				continue;
			}
			if (c != C_BEG) {
				return false;
			}
			if (scanUnit(buf, pos).twoBank) {
				return true;
			}
			int end = skipUnit(buf, pos);
			if (end < 0) {
				return false;
			}
			pos = end;
		}
		return false;
	}

	/** Offset just past the END checksum of the unit at pos, or -1. */
	private static int skipUnit(byte[] buf, int pos) throws IOException {
		boolean longf = false;
		pos++;
		while (pos < buf.length) {
			int c = buf[pos++] & 0xFF;
			int sBytes = longf ? 6 : 4;
			switch (c) {
				case C_LONGF: longf = true; break;
				case C_FEED: case C_INHB: case C_DBG: case C_PMO: case C_DMO: break;
				case C_LF: case C_LR: case C_LC: case C_LRP: case C_LRD:
				case C_SFL: case C_AFL: case C_SRL: case C_RT: case C_NWL:
					pos += 2; break;
				case C_AFF: case C_ARF: case C_AFR: case C_ARR: case C_INL: case C_BYL:
					pos += 4; break;
				case C_DBL: pos += 6; break;
				case C_RLL: pos += 8; break;
				case C_CXL: pos += 14; break;
				case C_MAIN: case C_LIBR: case C_ENTR: case C_REF: case C_ADS:
					pos += sBytes; break;
				case C_ASF: pos += sBytes + 2; break;
				case C_INC: case C_BYC: pos += sBytes + 4; break;
				case C_DBC: pos += sBytes + 6; break;
				case C_RLC: pos += sBytes + 8; break;
				case C_CXC: pos += sBytes + 14; break;
				case C_LNF: case C_ID30: pos += 2 + 2 * word(buf, pos); break;
				case C_DIC:
					while (word(buf, pos) != END_OF_LIST) {
						pos += 10;
					}
					pos += 2;
					break;
				case C_END: return pos + 2;
				default: return -1;
			}
		}
		return -1;
	}

	private BrfImage interpret(byte[] buf, MessageLog log, TaskMonitor monitor)
			throws CancelledException, IOException {

		BrfImage img = new BrfImage();
		img.twoBank = fileIsTwoBank(buf);

		// Per-bank state. Bank 0 = program bank (the only one in a one-bank
		// program), bank 1 = data bank (two-bank programs: DMO selects it, PMO
		// selects the program bank again). VERIFIED 2026-11-16 over the 13
		// two-bank files in NDInsight (all "-2" / "2BANK" variants): with a
		// separate CLC and base per bank, 1720 of 1724 fix-ups land on words
		// already loaded in the current bank and not on a REF word; with one
		// shared CLC, 48 land on words never loaded and 65 on REF words. The
		// 4 that remain (NK-100-2BANK-C03 file offset 0x1b10, SLIB-NRE-2B-B01
		// 0x9a94, 0xe236, 0x10180) are recorded as open in src/PLAN.md.
		// In data mode the files use LNF, LF, LRP, LRD, REF, ENTR, LIBR and AFL
		// but never LR or a fix-up, so "LR uses the current bank's base" cannot
		// be told apart from "LR always uses the program base" by these files.
		int[] clc = new int[2];      // current location counter per bank
		int[] base = new int[2];     // CLC-at-BEG minus 1 per bank (see BEG)
		int[] spc = new int[] { 0, -1 }; // image space per bank (-1 = data bank not made yet)
		int[] pages = new int[] { 1, 1 };
		int cur = 0;                 // 0 after BEG and PMO, 1 after DMO
		int pos = 0;
		boolean longf = false;
		boolean inUnit = false;
		int sum = 0;                 // running checksum of the current unit
		UnitInfo unit = null;
		if (img.twoBank) {
			// The data bank's first address is not in the BRF; it is given at
			// load time. 0 is this loader's choice (stated in the file header).
			spc[1] = img.newSpace("BRF_DATA", true);
		}

		while (pos < buf.length) {
			monitor.checkCancelled();
			int c = buf[pos] & 0xFF;

			if (!inUnit) {
				// Between units only FEED padding, BEG and EOF are meaningful.
				if (c == C_FEED) {
					pos++;
					continue;
				}
				if (c == C_EOF) {
					img.sawEof = true;
					pos++;
					long trailing = buf.length - pos;
					if (trailing > 0) {
						log.appendMsg(String.format(
								"%d bytes after EOF ignored (BRF Editor concatenations?)", trailing));
					}
					break;
				}
				if (c != C_BEG) {
					log.appendMsg(String.format(
							"Unexpected control byte 0%o outside a unit at offset 0x%X — stopping",
							c, pos));
					break;
				}
				// BEG: start a unit. LONGF resets here (verified against real files).
				inUnit = true;
				longf = false;
				sum = C_BEG;
				cur = 0;
				unit = new UnitInfo();
				unit.number = img.units.size() + 1;
				unit.fileOffset = pos;
				// A unit that would pass 0177777 starts in a fresh space (see
				// BrfImage). A unit that sets an absolute address (SFL) is
				// placed where it says.
				UnitScan sc = scanUnit(buf, pos);
				for (int b = 0; b < 2; b++) {
					if (spc[b] < 0 || sc.absolute) {
						continue;
					}
					if (clc[b] + sc.extent[b] > MEM_WORDS) {
						pages[b]++;
						String name = (b == 0 ? "BRF_PAGE" : "BRF_DATA_PAGE") + pages[b];
						spc[b] = img.newSpace(name, b == 1);
						log.appendMsg(String.format(
								"Unit %d (%d words) does not fit below 0200000 after 0%06o; " +
										"it and the units after it go to overlay space %s",
								unit.number, sc.extent[b], clc[b], name));
						clc[b] = 0;
					}
				}
				// Relative addresses count the unit's first word as 1, so the
				// base the loader adds is CLC-at-BEG MINUS 1 (LR W1 stores
				// L + W1 - 1, AFR W1,W2 patches L + W2 - 1, SRL W1 sets CLC to
				// L + W1 - 1). Measured on the real BRF-LINKER C01 (NDInsight
				// BRF-FILE-FORMAT.md section 3, 2026-10-12) and re-checked
				// 2026-11-16 over 4701 fix-ups in five files (X25-LINK,
				// X25-SUPVISOR, X25C-MAIN, X25-UTILITY C00, encos-err-i-b01):
				// with PB = CLC-1 every fix-up target is an already-loaded word;
				// with PB = CLC, 105 hit REF words.
				base[0] = (clc[0] - 1) & WORD_MASK;
				base[1] = (clc[1] - 1) & WORD_MASK;
				unit.pb = clc[0];   // shown to the user: address of the unit's first word
				unit.space = spc[0];
				if (spc[1] >= 0) {
					unit.dataPb = clc[1];
					unit.dataSpace = spc[1];
				}
				img.units.add(unit);
				pos++;
				continue;
			}

			pos++;
			sum = (sum + c) & WORD_MASK;

			switch (c) {
				case C_FEED:
					break;

				case C_LONGF:
					longf = true;
					unit.longf = true;
					break;

				case C_LF: case C_LR: case C_LC: {
					int w1 = word(buf, pos);
					sum = (sum + w1) & WORD_MASK;
					pos += 2;
					int v = w1;
					if (c == C_LR) {
						v = (w1 + base[cur]) & WORD_MASK;
					}
					else if (c == C_LC) {
						// LC adds CDB — the manual defines CDB as "the COMMON data
						// base". 6 LC groups occur in the 48 NDInsight files, all in
						// one-bank files. We use the most recently ASF-allocated
						// block start as CDB; if no COMMON exists yet the word is
						// stored unrelocated and logged.
						if (img.commonTop == 0177777) {
							log.appendMsg(String.format(
									"LC at 0%06o with no COMMON block allocated — stored unrelocated",
									clc[cur]));
						}
						else {
							v = (w1 + img.commonTop + 1) & WORD_MASK;
						}
					}
					store(img, loc(spc[cur], clc[cur]), v);
					clc[cur] = advance(clc[cur], 1, unit, log);
					break;
				}

				case C_AFF: case C_ARF: case C_AFR: case C_ARR: {
					int w1 = word(buf, pos);
					int w2 = word(buf, pos + 2);
					sum = (sum + w1 + w2) & WORD_MASK;
					pos += 4;
					int target = (c == C_AFR || c == C_ARR) ? (w2 + base[cur]) & WORD_MASK : w2;
					int add    = (c == C_ARF || c == C_ARR) ? (w1 + base[cur]) & WORD_MASK : w1;
					int l = loc(spc[cur], target);
					store(img, l, (img.read(l) + add) & WORD_MASK);
					break;
				}

				case C_SFL: {
					int w1 = word(buf, pos);
					sum = (sum + w1) & WORD_MASK;
					pos += 2;
					clc[cur] = w1;
					break;
				}

				case C_AFL: {
					int w1 = word(buf, pos);
					sum = (sum + w1) & WORD_MASK;
					pos += 2;
					// advance and fill zeros
					for (int i = 0; i < w1; i++) {
						store(img, loc(spc[cur], clc[cur] + i), 0);
					}
					clc[cur] = advance(clc[cur], w1, unit, log);
					break;
				}

				case C_SRL: {
					int w1 = word(buf, pos);
					sum = (sum + w1) & WORD_MASK;
					pos += 2;
					clc[cur] = (base[cur] + w1) & WORD_MASK;
					break;
				}

				case C_MAIN: case C_LIBR: case C_ENTR: case C_REF: {
					int sBytes = longf ? 6 : 4;
					for (int i = 0; i < sBytes; i += 2) {
						sum = (sum + word(buf, pos + i)) & WORD_MASK;
					}
					String name = decodeSymbol(buf, pos, sBytes);
					pos += sBytes;
					if (c == C_MAIN) {
						// The start address only; see load() for why the name is
						// not entered as a symbol a REF can link to.
						unit.main = name;
						unit.mainLoc = loc(spc[cur], clc[cur]);
						break;
					}
					BrfSymbol sym = img.symbols.computeIfAbsent(name, k -> {
						BrfSymbol s = new BrfSymbol();
						s.name = k;
						return s;
					});
					if (c == C_LIBR) {
						unit.libr.add(name);
					}
					else if (c == C_ENTR) {
						unit.entr.add(name);
						if (sym.defined) {
							log.appendMsg(String.format(
									"Symbol %s redefined in unit %d (old 0%06o, new 0%06o)",
									name, unit.number, sym.value, clc[cur]));
						}
						sym.defined = true;
						sym.value = clc[cur];
						sym.space = spc[cur];
						sym.definedInUnit = unit.number;
						resolveChain(img, sym, log);
					}
					else { // C_REF — consumes one word at CLC (see class doc)
						// ND-60.066.04 section 2.5: a symbol already defined is
						// stored at once; otherwise the word gets a link to the
						// previous reference of the same symbol (177777 for the
						// first) and becomes the head of the chain. A fix-up that
						// follows (e.g. AFR adding 26 to the word: "address of
						// AIL0 + 26" in NK-100-1BANK-C03.BRF) then adds to the
						// real address, as on the machine.
						int l = loc(spc[cur], clc[cur]);
						sym.refLocations.add(l);
						if (sym.defined) {
							store(img, l, sym.value);
						}
						else {
							Integer head = sym.chainHeads.get(spc[cur]);
							store(img, l, head == null ? END_OF_LIST : head & WORD_MASK);
							sym.chainHeads.put(spc[cur], l);
						}
						clc[cur] = advance(clc[cur], 1, unit, log);
					}
					break;
				}

				case C_END: {
					int stored = word(buf, pos);
					pos += 2;
					unit.checksumStored = stored;
					unit.checksumComputed = sum;
					unit.checksumOk = ((sum + stored) & WORD_MASK) == 0;
					if (!unit.checksumOk) {
						img.checksumFailures++;
						log.appendMsg(String.format(
								"Unit %d checksum MISMATCH (sum=0%06o stored=0%06o)",
								unit.number, sum, stored));
					}
					unit.endClc = clc[0];
					if (unit.dataSpace >= 0) {
						unit.dataEnd = clc[1];
					}
					inUnit = false;
					unit = null;
					break;
				}

				case C_INHB:
					unit.inhibit = true;
					log.appendMsg(String.format(
							"Unit %d flagged INHB: compilation errors occurred", unit.number));
					break;

				case C_EOF:
					// EOF inside a unit is a syntax error; be tolerant and stop.
					log.appendMsg(String.format(
							"EOF inside unit %d at offset 0x%X — stopping", unit.number, pos - 1));
					img.sawEof = true;
					pos = buf.length;
					break;

				case C_LNF: {
					int count = word(buf, pos);
					sum = (sum + count) & WORD_MASK;
					pos += 2;
					if (pos + count * 2 > buf.length) {
						throw new IOException(String.format(
								"LNF count %d overruns file at offset 0x%X", count, pos));
					}
					for (int i = 0; i < count; i++) {
						int w = word(buf, pos);
						sum = (sum + w) & WORD_MASK;
						pos += 2;
						store(img, loc(spc[cur], clc[cur] + i), w);
					}
					clc[cur] = advance(clc[cur], count, unit, log);
					break;
				}

				case C_RT: case C_NWL: {
					int w1 = word(buf, pos);
					sum = (sum + w1) & WORD_MASK;
					pos += 2;
					if (c == C_RT) {
						unit.rtPriority = w1;
						log.appendMsg(String.format("Unit %d real-time priority: 0%o",
								unit.number, w1));
					}
					break;
				}

				case C_ASF: {
					int sBytes = longf ? 6 : 4;
					for (int i = 0; i < sBytes; i += 2) {
						sum = (sum + word(buf, pos + i)) & WORD_MASK;
					}
					String name = decodeSymbol(buf, pos, sBytes);
					pos += sBytes;
					int len = word(buf, pos);
					sum = (sum + len) & WORD_MASK;
					pos += 2;
					BrfSymbol sym = img.symbols.computeIfAbsent(name, k -> {
						BrfSymbol s = new BrfSymbol();
						s.name = k;
						return s;
					});
					if (!sym.defined) {
						sym.defined = true;
						sym.definedInUnit = unit.number;
						sym.isCommon = true;
						sym.commonLength = len;
						if (img.twoBank) {
							// Two-bank: "COMMON blocks are allocated like all other
							// data areas, i.e., from the present data load address
							// upwards" (ND-60.066.04 section 2.6). No ASF occurs in
							// the 48 NDInsight files, so this rests on the manual.
							sym.space = spc[1];
							sym.value = clc[1];
							for (int i = 0; i < len; i++) {
								img.reserved.get(spc[1])[(clc[1] + i) & WORD_MASK] = true;
							}
							clc[1] = advance(clc[1], len, unit, log);
						}
						else {
							// 1-bank rule: allocate downward from the upper bound.
							img.commonTop -= len;
							sym.space = 0;
							sym.value = (img.commonTop + 1) & WORD_MASK;
							for (int i = 0; i < len; i++) {
								img.reserved.get(0)[(sym.value + i) & WORD_MASK] = true;
							}
						}
						log.appendMsg(String.format("COMMON %s: %d words at 0%06o (%s)",
								name, len, sym.value, img.spaceNames.get(sym.space)));
						resolveChain(img, sym, log);
					}
					// Succeeding declarations cannot expand the block (section 2.6).
					break;
				}

				case C_ADS: {
					int sBytes = longf ? 6 : 4;
					for (int i = 0; i < sBytes; i += 2) {
						sum = (sum + word(buf, pos + i)) & WORD_MASK;
					}
					String name = decodeSymbol(buf, pos, sBytes);
					pos += sBytes;
					BrfSymbol sym = img.symbols.get(name);
					int l = loc(spc[cur], clc[cur] - 1);
					if (sym != null && sym.defined) {
						store(img, l, (img.read(l) + sym.value) & WORD_MASK);
					}
					else {
						log.appendMsg(String.format(
								"ADS references undefined COMMON symbol %s at 0%06o", name, l & WORD_MASK));
					}
					break;
				}

				case C_ID30: {
					// Undocumented ("not used" per manual) but observed in PLANC
					// output: framed like LNF, payload is ASCII (e.g. PLANC-1BANK-G00).
					int count = word(buf, pos);
					sum = (sum + count) & WORD_MASK;
					pos += 2;
					StringBuilder ascii = new StringBuilder();
					for (int i = 0; i < count; i++) {
						int w = word(buf, pos);
						sum = (sum + w) & WORD_MASK;
						pos += 2;
						ascii.append(printable((w >> 8) & 0xFF));
						ascii.append(printable(w & 0xFF));
					}
					unit.idStamp = ascii.toString().trim();
					log.appendMsg(String.format("Unit %d id stamp (ctrl 30): %s",
							unit.number, unit.idStamp));
					break;
				}

				case C_INL: case C_BYL: {
					int w1 = word(buf, pos);
					int w2 = word(buf, pos + 2);
					sum = (sum + w1 + w2) & WORD_MASK;
					pos += 4;
					int l = loc(spc[cur], w1 + base[cur]);
					if (c == C_INL) {
						store(img, l, w2);
					}
					else {
						storeByte(img, l, w2);
					}
					break;
				}

				case C_DBL: case C_RLL: case C_CXL: {
					int n = (c == C_DBL) ? 2 : (c == C_RLL) ? 3 : 6;
					int w1 = word(buf, pos);
					sum = (sum + w1) & WORD_MASK;
					pos += 2;
					int target = (w1 + base[cur]) & WORD_MASK;
					for (int i = 0; i < n; i++) {
						int w = word(buf, pos);
						sum = (sum + w) & WORD_MASK;
						pos += 2;
						store(img, loc(spc[cur], target + i), w);
					}
					break;
				}

				case C_INC: case C_DBC: case C_RLC: case C_CXC: case C_BYC: {
					// S-group = COMMON block name (must be defined; value = ADR),
					// then W4 = offset, W5.. = data.
					int n = (c == C_INC || c == C_BYC) ? 1 : (c == C_DBC) ? 2 : (c == C_RLC) ? 3 : 6;
					int sBytes = longf ? 6 : 4;
					for (int i = 0; i < sBytes; i += 2) {
						sum = (sum + word(buf, pos + i)) & WORD_MASK;
					}
					String name = decodeSymbol(buf, pos, sBytes);
					pos += sBytes;
					int w4 = word(buf, pos);
					sum = (sum + w4) & WORD_MASK;
					pos += 2;
					BrfSymbol sym = img.symbols.get(name);
					boolean known = sym != null && sym.defined;
					if (!known) {
						log.appendMsg(String.format(
								"COMMON store references undefined block %s — data skipped", name));
					}
					for (int i = 0; i < n; i++) {
						int w = word(buf, pos);
						sum = (sum + w) & WORD_MASK;
						pos += 2;
						if (known) {
							int l = loc(sym.space, w4 + sym.value + i);
							if (c == C_BYC) {
								storeByte(img, l, w);
							}
							else {
								store(img, l, w);
							}
						}
					}
					break;
				}

				case C_DBG:
					break;

				case C_PMO:
					cur = 0;
					break;

				case C_DMO:
					cur = 1;
					break;

				case C_LRP: case C_LRD: {
					// LR with the base of the program bank (LRP) or the data bank
					// (LRD), stored in the CURRENT bank: the data bank holds
					// program addresses (LRP in DMO mode, 1925 times in the 13
					// two-bank files) and the program bank data addresses.
					int w1 = word(buf, pos);
					sum = (sum + w1) & WORD_MASK;
					pos += 2;
					int b = (c == C_LRP) ? 0 : 1;
					store(img, loc(spc[cur], clc[cur]), (w1 + base[b]) & WORD_MASK);
					clc[cur] = advance(clc[cur], 1, unit, log);
					break;
				}

				case C_DIC: {
					// Library dictionary: 5-word elements (3-word name + 2-word
					// byte pointer) until 177777. Only used to speed up selective
					// loading — we load everything, so just log it.
					int entries = 0;
					while (true) {
						int w = word(buf, pos);
						sum = (sum + w) & WORD_MASK;
						pos += 2;
						if (w == END_OF_LIST) {
							break;
						}
						for (int i = 0; i < 4; i++) {
							sum = (sum + word(buf, pos)) & WORD_MASK;
							pos += 2;
						}
						entries++;
					}
					log.appendMsg(String.format("Unit %d: dictionary with %d entries (ignored)",
							unit.number, entries));
					break;
				}

				default:
					throw new IOException(String.format(
							"Illegal BRF control number 0%o at offset 0x%X (unit %d)",
							c, pos - 1, unit.number));
			}
		}

		if (inUnit) {
			log.appendMsg("File ended inside a unit (no END group)");
		}

		// References are resolved when the symbol is defined (resolveChain).
		// Symbols never defined keep their chain: each reference word holds
		// the address of the previous reference, the first holds 0177777 -
		// what the loader's memory holds before the library or SINTRAN
		// supplies the symbol. They are reported by load().

		return img;
	}

	/**
	 * Move a CLC forward. Passing 0177777 inside a unit cannot happen when
	 * {@link #scanUnit} measured the unit right; if it does anyway it is logged
	 * loudly (the words wrap to 0 in the same space).
	 */
	private static int advance(int clc, int n, UnitInfo unit, MessageLog log) {
		int next = clc + n;
		if (next > MEM_WORDS) {
			log.appendMsg(String.format(
					"ERROR: unit %d passes 0177777 (CLC 0%06o + %d); its words wrap to 0 " +
							"and overwrite what is there", unit.number, clc, n));
		}
		return next & WORD_MASK;
	}

	/**
	 * Walk the reference chains of a symbol that has just been defined and
	 * store its value in every word on them (ND-60.066.04 section 2.5: ADR
	 * points at the last reference, each reference word points at the one
	 * before, the first holds 0177777). One chain per image space (see
	 * BrfSymbol.chainHeads). A link that leaves the loaded words, or a chain
	 * longer than the number of references read, means a word on the chain was
	 * changed after its REF; the walk stops there and the case is logged.
	 */
	private static void resolveChain(BrfImage img, BrfSymbol sym, MessageLog log) {
		for (Map.Entry<Integer, Integer> e : sym.chainHeads.entrySet()) {
			int space = e.getKey();
			int l = e.getValue();
			int steps = 0;
			while (true) {
				if (!img.isDefined(l) || steps > sym.refLocations.size()) {
					log.appendMsg(String.format(
							"Reference chain of %s is broken at 0%06o in %s (a word on it was " +
									"changed after its REF); remaining references not patched",
							sym.name, l & WORD_MASK, img.spaceNames.get(space)));
					break;
				}
				int next = img.read(l);
				store(img, l, sym.value);
				steps++;
				if (next == END_OF_LIST) {
					break;
				}
				l = loc(space, next);
			}
		}
		sym.chainHeads.clear();
	}

	/** Append to an existing comment instead of overwriting it. */
	private static void appendComment(Listing listing, Address a, CommentType type, String text) {
		String prev = listing.getComment(type, a);
		listing.setComment(a, type, prev == null || prev.isEmpty() ? text : prev + "\n" + text);
	}

	/** Store a word at an image location and mark it loaded. */
	private static void store(BrfImage img, int loc, int value) {
		img.words.get(loc >>> 16)[loc & WORD_MASK] = value & WORD_MASK;
		img.defined.get(loc >>> 16)[loc & WORD_MASK] = true;
	}

	/**
	 * BYL/BYC semantics: W bits 0-7 go to the target's bits 0-7 if W bit 15 = 0,
	 * to bits 8-15 if W bit 15 = 1.
	 */
	private static void storeByte(BrfImage img, int loc, int w) {
		int b = w & 0xFF;
		int old = img.read(loc);
		int v = ((w & 0x8000) != 0) ? (old & 0x00FF) | (b << 8)
									: (old & 0xFF00) | b;
		store(img, loc, v);
	}

	private static int word(byte[] buf, int pos) throws IOException {
		if (pos + 2 > buf.length) {
			throw new IOException("Unexpected end of BRF file at offset 0x" +
					Integer.toHexString(pos));
		}
		// P-groups are big-endian: MSB first (verified — checksums fail otherwise).
		return ((buf[pos] & 0xFF) << 8) | (buf[pos + 1] & 0xFF);
	}

	/**
	 * Decode an S-group: six-bit characters, right-justified, zero-padded on
	 * the left, packed MSB-first. Each code is the low six bits of the ASCII
	 * character (see class doc): 0 is a space (padding), 01-037 are letters
	 * and [\]^_ (ASCII 0100 + code), 040-077 are space, digits and
	 * punctuation (ASCII = code).
	 * 4 bytes = 32 bits = 5 chars (top 2 bits zero); 6 bytes = 48 bits = 7 chars
	 * (top 6 bits zero).
	 *
	 * FORTRAN/BASIC statement-number labels (ND-60.066.04 section 2.3: first two
	 * and last two bytes zero, bytes 3-4 hold the label number) are not names;
	 * they are returned as "STMT_" + the decimal number.
	 */
	static String decodeSymbol(byte[] buf, int pos, int sBytes) throws IOException {
		if (pos + sBytes > buf.length) {
			throw new IOException("Truncated S-group at offset 0x" + Integer.toHexString(pos));
		}
		if (sBytes == 6 && buf[pos] == 0 && buf[pos + 1] == 0 &&
			buf[pos + 4] == 0 && buf[pos + 5] == 0 && (buf[pos + 2] != 0 || buf[pos + 3] != 0)) {
			return "STMT_" + (((buf[pos + 2] & 0xFF) << 8) | (buf[pos + 3] & 0xFF));
		}
		long bits = 0;
		for (int i = 0; i < sBytes; i++) {
			bits = (bits << 8) | (buf[pos + i] & 0xFF);
		}
		int nChars = (sBytes == 6) ? 7 : 5;
		StringBuilder sb = new StringBuilder(nChars);
		for (int i = nChars - 1; i >= 0; i--) {
			int ch = (int) ((bits >> (i * 6)) & 0x3F);
			// Code 0 is a SPACE (BRF-FILE-FORMAT.md section 4, checked against
			// the BRF linker's LIST-BRF-ENTRIES, 462 of 462 names), not '@'.
			// Names are padded with it on the left (MAC, PLANC entry names) and
			// on the right (PLANC internal labels such as "AIL0" + 2 pad codes,
			// seen in NK-100-1BANK-C03.BRF); the trim below removes both.
			sb.append((char) (ch == 0 ? ' ' : ch < 040 ? 0100 + ch : ch));
		}
		String s = sb.toString().trim();
		return s.isEmpty() ? "BLANK" : s;
	}

	private static char printable(int b) {
		return (b >= 0x20 && b < 0x7F) ? (char) b : '.';
	}

	/**
	 * BRF symbols may contain characters Ghidra labels can't (e.g. space).
	 * Six-bit code covers ASCII 040-137 (low six bits of ASCII), most of which is fine; replace
	 * anything outside [A-Za-z0-9_$*+-.:] with '_'.
	 */
	private static String sanitizeLabel(String name) {
		StringBuilder sb = new StringBuilder(name.length());
		for (int i = 0; i < name.length(); i++) {
			char ch = name.charAt(i);
			if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
				(ch >= '0' && ch <= '9') || ch == '_' || ch == '$' ||
				ch == '*' || ch == '+' || ch == '-' || ch == '.' || ch == ':') {
				sb.append(ch);
			}
			else {
				sb.append('_');
			}
		}
		return sb.toString();
	}
}
