using System;
using System.IO;
using System.Text;
using NDGen.Core;
using NDGen.Core.Models;
using System.Threading.Tasks;
using System.Diagnostics;
using System.IO.Compression;

namespace NDGen.Generators.Ghidra
{
    /// <summary>
    /// Generates SLEIGH specification for the ND-100 processor
    /// </summary>
    public class GhidraSleighGenerator : BaseGenerator
    {
        private readonly DefinitionLoader _loader;
        private readonly string _outputPath;
        private readonly string _languagesPath;

        public GhidraSleighGenerator(string outputPath, DefinitionLoader loader) : base(outputPath, loader)
        {
            _loader = loader ?? throw new ArgumentNullException(nameof(loader));
            _outputPath = outputPath ?? throw new ArgumentNullException(nameof(outputPath));
            
            // NEW: Create extension-compatible directory structure
            // outputPath/ND-100/data/languages/ (official Ghidra extension format)
            var extensionPath = Path.Combine(_outputPath, "ND-100");
            _languagesPath = Path.Combine(extensionPath, "data", "languages");
            
            // Ensure all required directories exist
            Directory.CreateDirectory(_outputPath);
            Directory.CreateDirectory(extensionPath);
            Directory.CreateDirectory(Path.Combine(extensionPath, "data"));
            Directory.CreateDirectory(_languagesPath);
        }

        public override void Generate()
        {
            try
            {
                // Load base template
                var templatePath = Path.Combine(BaseDirectory, "src", "NDGen.Generators.Ghidra", "Ghidra", "Templates", "nd100-base.slaspec");
                var baseTemplate = File.ReadAllText(templatePath);
                
                // Generate dynamic instruction patterns
                var instructions = GenerateInstructionPatterns();
                
                // Replace placeholder with generated instructions  
                var finalSpec = baseTemplate.Replace("# PLACEHOLDER_INSTRUCTIONS - Will be replaced with generated instructions", instructions);
                
                // Write final SLEIGH file
                var sleighPath = Path.Combine(_languagesPath, "nd100.slaspec");
                File.WriteAllText(sleighPath, finalSpec);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ERROR: Failed to generate SLEIGH spec: {ex.Message}");
                Console.WriteLine($"ERROR: Stack trace: {ex.StackTrace}");
                throw;
            }
            
            // Copy static XML templates 
            CopyTemplateFiles();

            // Validate the generated output - temporarily disabled during word-addressed CPU implementation
            // var validator = new GhidraOutputValidator(_outputPath);
            // if (!validator.ValidateOutput())
            // {
            //     var errors = validator.GetErrors();
            //     throw new InvalidOperationException(
            //         $"Ghidra output validation failed:\n{string.Join("\n", errors)}");
            // }
            Console.WriteLine("⚠️  Schema validation disabled during word-addressed CPU implementation");
        }

        private string GenerateInstructionPatterns()
        {
            var sb = new StringBuilder();
            sb.AppendLine("# ND-100 Instructions Generated from YAML Definitions");
            sb.AppendLine();

            // Generate SLEIGH patterns for all loaded instructions
            // Constructor patterns always come from YAML (correct opcodes/masks)
            // P-code bodies are loaded from .sinc template files when available
            var instructions = _loader.GetInstructions();
            for (int i = 0; i < instructions.Count; i++)
            {
                var instruction = instructions[i];

                try
                {
                    var sleighPattern = GenerateSleighInstruction(instruction);
                    sb.AppendLine(sleighPattern);
                    sb.AppendLine();
                }
                catch (Exception ex)
                {
                    sb.AppendLine($"# ERROR: Could not generate SLEIGH for {instruction.Name}: {ex.Message}");
                    sb.AppendLine();
                }
            }
            
            return sb.ToString();
        }

        private string GenerateSleighInstruction(InstructionDefinition instruction)
        {
            var sb = new StringBuilder();

            // Convert octal opcode to hex
            var opcodeOctal = instruction.Opcode.Trim().TrimStart('0');
            if (string.IsNullOrEmpty(opcodeOctal)) opcodeOctal = "0";
            var opcodeValue = Convert.ToInt32(opcodeOctal, 8);

            // Check if .sinc file contains full constructors (starts with : or #)
            // This handles instructions like JMP/JPL that need multiple constructors
            if (instruction.Name == "MON")
            {
                // The CPU does the same for every MON n; the extra returns are SINTRAN's, per
                // call number, and come from mon-calls.json. Each such call gets its own
                // constructor, which SLEIGH prefers over the general one below.
                sb.Append(GenerateMonReturnConstructors());
            }

            var fullConstructor = LoadFullConstructor(instruction.Name);
            if (fullConstructor != null)
            {
                sb.Append(fullConstructor);
                if (!fullConstructor.EndsWith("\n"))
                    sb.AppendLine();
                return sb.ToString();
            }

            // Use mask to determine pattern matching bits
            if (!string.IsNullOrEmpty(instruction.Mask))
            {
                var maskBinary = instruction.Mask.Replace("_", "");
                var maskValue = Convert.ToInt32(maskBinary, 2);

                // Count the number of contiguous '1' bits in the mask starting from MSB
                int contiguousBits = 0;
                int tempMask = maskValue;
                while (tempMask != 0 && (tempMask & 0x8000) != 0)
                {
                    contiguousBits++;
                    tempMask <<= 1;
                }

                // Route to appropriate pattern generator based on mask type
                // Returns true if constructors + P-code were fully emitted (e.g., TRA/TRR per-register)
                bool fullyHandled = GenerateConstructorForMask(sb, instruction, maskBinary, maskValue, opcodeValue, contiguousBits);
                if (fullyHandled)
                    return sb.ToString();
            }
            else
            {
                // Fallback to top 5 bits if no mask is provided
                var topBits = (opcodeValue >> 11) & 0x1F;
                var fallbackClass = instruction.InstructionClass ?? "";

                var instrName = instruction.Name;
                if (fallbackClass == "memory_transfer")
                {
                    // Memory reference without mask: use addr sub-table
                    sb.AppendLine($":{instrName} addr is op5=0x{topBits:X2} & addr {{  # {instruction.Opcode} octal = 0x{opcodeValue:X4}, top 5 bits (addr)");
                }
                else
                {
                    sb.AppendLine($":{instrName} disp is op5=0x{topBits:X2} & disp {{  # {instruction.Opcode} octal = 0x{opcodeValue:X4}, top 5 bits = 0x{topBits:X2} (no mask)");
                }
            }

            // Load P-code body from .sinc template file
            var pcodeBody = LoadPCodeBody(instruction.Name);
            if (pcodeBody != null)
            {
                sb.Append(pcodeBody);
                if (!pcodeBody.EndsWith("\n"))
                    sb.AppendLine();
            }
            else
            {
                // No .sinc file found — emit placeholder
                sb.AppendLine($"    # WARNING: No P-code file for {instruction.Name}");
                sb.AppendLine("    local nop_placeholder:1 = 0;");
            }

            // A register operation whose destination is P is a jump (ND-06.014.2A: "DP -
            // Program counter as destination"). The rop_jmp / reg3_jmp sub-tables in
            // nd100-base.slaspec add "goto [P]" for that case and nothing otherwise; their
            // p-code must run AFTER the body has written P, so the build goes last.
            //
            // Only an instruction that really WRITES its destination register can write P.
            // The same header shape is shared by instructions that write no register named
            // by that field (EXR, RDIV, RMPY, LRB, SRB, MOVEW: they run a register, write
            // A and D, or move a register bank / memory). Those must not get the jump, so
            // the sub-table is taken off their header again.
            var built = sb.ToString();
            if (built.Contains("& rop_jmp {"))
            {
                if (System.Text.RegularExpressions.Regex.IsMatch(built, @"(?m)^\s*rop_dst\s*="))
                    sb.AppendLine("    build rop_jmp;");
                else
                    sb.Replace(" & rop_jmp {", " {");
            }
            else if (built.Contains("& reg3_jmp {"))
            {
                if (System.Text.RegularExpressions.Regex.IsMatch(built, @"(?m)^\s*reg3\s*="))
                    sb.AppendLine("    build reg3_jmp;");
                else
                    sb.Replace(" & reg3_jmp {", " {");
            }

            sb.AppendLine("}");

            return sb.ToString();
        }

        private bool GenerateConstructorForMask(StringBuilder sb, InstructionDefinition instruction,
            string maskBinary, int maskValue, int opcodeValue, int contiguousBits)
        {
            var name = instruction.Name;

            // ---- Contiguous mask patterns ----
            if (contiguousBits <= 5 && maskBinary == "1111100000000000")
            {
                // 5-bit contiguous mask: memory reference instructions use addr sub-table,
                // IOX/IOT use io_addr (full 11-bit device address), others keep disp
                var opVal = (opcodeValue >> 11) & 0x1F;
                var instrClass = instruction.InstructionClass ?? "";

                if (instrClass == "memory_transfer" && (name == "LDD" || name == "STD" || name == "LDF" || name == "STF" || name == "FAD" || name == "FSB" || name == "FMU" || name == "FDV"))
                {
                    // Multi-word memory reference: use ea_addr sub-table (exports raw address, not value)
                    // so P-code can access EA+1, EA+2 for double/float word operations
                    sb.AppendLine($":{name} ea_addr is op5=0x{opVal:X2} & ea_addr {{  # {instruction.Opcode} octal = 0x{opcodeValue:X4}, 5-bit mask (ea_addr)");
                }
                else if (instrClass == "memory_transfer")
                {
                    // Single-word memory reference: LDA, STA, ADD, etc.
                    sb.AppendLine($":{name} addr is op5=0x{opVal:X2} & addr {{  # {instruction.Opcode} octal = 0x{opcodeValue:X4}, 5-bit mask (addr)");
                }
                else if (name == "IOX" || name == "IOT")
                {
                    // I/O instructions: use io_ref sub-table for proper io_space references
                    // io_dir in pattern so P-code can check direction (bit 0: 0=in, 1=out)
                    sb.AppendLine($":{name} io_ref is op5=0x{opVal:X2} & io_dir & io_ref {{  # {instruction.Opcode} octal = 0x{opcodeValue:X4}, 5-bit mask (I/O)");
                }
                else if (name == "IOXT")
                {
                    // IOXT uses T register for address, no immediate I/O field
                    sb.AppendLine($":{name} io_addr is op5=0x{opVal:X2} & io_addr {{  # {instruction.Opcode} octal = 0x{opcodeValue:X4}, 5-bit mask (I/O)");
                }
                else
                {
                    // Other 5-bit instructions (shouldn't happen, but fallback)
                    sb.AppendLine($":{name} disp is op5=0x{opVal:X2} & disp {{  # {instruction.Opcode} octal = 0x{opcodeValue:X4}, 5-bit mask");
                }
            }
            else if (contiguousBits <= 8 && maskBinary == "1111111100000000")
            {
                // 8-bit contiguous mask: JMP, JAZ, WAIT, etc.
                var opVal = (opcodeValue >> 8) & 0xFF;
                // Check for modifier bits outside the mask (e.g., COPY = RADD CLD has bit 6 set)
                int extraBits = opcodeValue & ~maskValue;
                if (extraBits != 0)
                {
                    // Alias with register operands and extra modifier bit constraints
                    var extraConstraints = new StringBuilder();
                    if ((extraBits & 0x0040) != 0) extraConstraints.Append(" & rop_cld=1");
                    sb.AppendLine($":{name} rop_src_d rop_dst_d is op8=0x{opVal:X2}{extraConstraints} & rop_src_d & rop_dst_d & rop_src & rop_dst & rop_jmp {{  # {instruction.Opcode} octal = 0x{opcodeValue:X4}, 8-bit alias mask");
                }
                else
                {
                    var instrClass8 = instruction.InstructionClass ?? "";
                    if (instrClass8 == "jump_on_condition" && name != "DNZ" && name != "NLZ")
                    {
                        // Conditional jumps: use rel_target for resolved addresses and Ghidra arrows
                        // DNZ/NLZ are FP conversion instructions, NOT jumps — they use disp for scaling factor
                        sb.AppendLine($":{name} rel_target is op8=0x{opVal:X2} & rel_target {{  # {instruction.Opcode} octal = 0x{opcodeValue:X4}, 8-bit mask (jump)");
                    }
                    else if (name == "MON")
                    {
                        // MON uses unsigned 8-bit monitor call number, not signed displacement
                        sb.AppendLine($":{name} imm8 is op8=0x{opVal:X2} & imm8 {{  # {instruction.Opcode} octal = 0x{opcodeValue:X4}, 8-bit mask (unsigned)");
                    }
                    else
                    {
                        sb.AppendLine($":{name} disp is op8=0x{opVal:X2} & disp {{  # {instruction.Opcode} octal = 0x{opcodeValue:X4}, 8-bit mask");
                    }
                }
            }
            else if (maskBinary == "1111111110000000")
            {
                // 9-bit contiguous mask: BANC, BAND, BSKP, etc.
                var opVal = (opcodeValue >> 7) & 0x1FF;
                sb.AppendLine($":{name} bit4 reg3_d is op9=0x{opVal:X3} & bit4 & reg3 & reg3_d {{  # {instruction.Opcode} octal = 0x{opcodeValue:X4}, 9-bit mask");
            }
            else if (maskBinary == "1111111111111111")
            {
                // 16-bit full match: ION, IOF, EXIT, etc.
                sb.AppendLine($":{name} is op16=0x{opcodeValue:X4} {{  # {instruction.Opcode} octal = 0x{opcodeValue:X4}, 16-bit mask");
            }
            // ---- 10-bit mask variants ----
            else if (maskBinary == "1111111111000111")
            {
                // 10-bit mask with 3-bit operand gap at bits 5-3 (LACB, LDATX, etc.)
                var op10Value = (opcodeValue >> 6) & 0x3FF;
                var fixed3Value = opcodeValue & 0x7;
                sb.AppendLine($":{name} disp3 is op10=0x{op10Value:X} & disp3 & fixed3=0x{fixed3Value:X} {{  # {instruction.Opcode} octal = 0x{opcodeValue:X4}, 10-bit mask");
            }
            else if (maskBinary == "1111111111000000")
            {
                // 10-bit mask with 6-bit operand (EXR only — uses source register, ignores dst bits)
                var op10Value = (opcodeValue >> 6) & 0x3FF;
                sb.AppendLine($":{name} rop_src_d is op10=0x{op10Value:X} & rop_src_d & rop_dst_d & rop_src & rop_dst & rop_jmp {{  # {instruction.Opcode} octal = 0x{opcodeValue:X4}, 10-bit mask");
            }
            // ---- 12-bit mask (TRA, TRR, MOVEW) ----
            else if (maskBinary == "1111111111110000")
            {
                var op12Value = (opcodeValue >> 4) & 0xFFF;
                if (name == "TRA" || name == "TRR")
                {
                    // Generate per-register constructors from YAML enum for readable decompiler output
                    GenerateTrxConstructors(sb, instruction, op12Value, name);
                    return true; // constructors + P-code already emitted
                }
                else
                {
                    sb.AppendLine($":{name} reg4 is op12=0x{op12Value:X3} & reg4 {{  # {instruction.Opcode} octal = 0x{opcodeValue:X4}, 12-bit mask");
                }
            }
            // ---- 13-bit mask (RCLR, RDCR, RINC) ----
            else if (maskBinary == "1111111111111000")
            {
                var op13Value = (opcodeValue >> 3) & 0x1FFF;
                sb.AppendLine($":{name} reg3_d is op13=0x{op13Value:X4} & reg3_d & reg3 & reg3_jmp {{  # {instruction.Opcode} octal = 0x{opcodeValue:X4}, 13-bit mask");
            }
            // ---- Non-contiguous mask: SKP (1111_1000_1100_0000) ----
            else if (maskBinary == "1111100011000000")
            {
                // SKP: top 5 bits (15-11) + bits 7-6 must be 00 + condition(10-8) + sr(5-3) + dr(2-0)
                // Display order: SKP IF <dr> <condition> <sr> (ND-100 convention)
                var op5Value = (opcodeValue >> 11) & 0x1F;
                sb.AppendLine($":{name} \"IF\" skp_dr_d skp_cond skp_sr_d is op5=0x{op5Value:X2} & skp_cond & skp_fixed=0x0 & skp_sr_d & skp_dr_d & skp_sr & skp_dr {{  # {instruction.Opcode} octal = 0x{opcodeValue:X4}, SKP non-contiguous mask");
            }
            // ---- Non-contiguous mask: SHA/SHD/SHT/SAD (1111_1001_1000_0000) ----
            else if (maskBinary == "1111100110000000")
            {
                // Shift instructions: mask has gap at bits 10-9 (shift type).
                // Use op5 for bits 15-11 + shift_reg for bits 8-7 (register selector).
                var op5Value = (opcodeValue >> 11) & 0x1F;
                var shiftRegValue = (opcodeValue >> 7) & 0x3;
                sb.AppendLine($":{name} shift_operand is op5=0x{op5Value:X2} & shift_reg=0x{shiftRegValue:X1} & shift_operand {{  # {instruction.Opcode} octal = 0x{opcodeValue:X4}, shift non-contiguous mask");
            }
            // ---- Fallback: use the largest contiguous field available ----
            else
            {
                // Try to match using contiguous bits from MSB
                if (contiguousBits >= 9)
                {
                    var opVal = (opcodeValue >> 7) & 0x1FF;
                    sb.AppendLine($":{name} shift7 is op9=0x{opVal:X3} & shift7 {{  # {instruction.Opcode} octal = 0x{opcodeValue:X4}, fallback {contiguousBits}-bit mask using op9");
                }
                else if (contiguousBits >= 5)
                {
                    var opVal = (opcodeValue >> 11) & 0x1F;
                    sb.AppendLine($":{name} disp is op5=0x{opVal:X2} & disp {{  # {instruction.Opcode} octal = 0x{opcodeValue:X4}, fallback {contiguousBits}-bit mask using op5");
                }
                else
                {
                    sb.AppendLine($"# WARNING: Cannot generate pattern for {name} with mask {instruction.Mask}");
                    sb.AppendLine($":{name} is op16=0x{opcodeValue:X4} {{  # {instruction.Opcode} octal, fallback to exact 16-bit match");
                }
            }
            return false;
        }

        /// <summary>
        /// Generates per-register constructors for TRA/TRR using YAML enum values.
        /// Each register selector gets its own constructor with a named pcodeop,
        /// producing readable decompiler output like read_STS() or write_PCR(A).
        /// </summary>
        private void GenerateTrxConstructors(StringBuilder sb, InstructionDefinition instruction,
            int op12Value, string name)
        {
            var operands = instruction.Operands;
            if (operands == null || operands.Count == 0)
            {
                sb.AppendLine($":{name} reg4 is op12=0x{op12Value:X3} & reg4 {{");
                sb.AppendLine($"    # {name}: no operands");
                sb.AppendLine("}");
                return;
            }

            // Find the enum operand
            List<EnumOption>? enumValues = null;
            for (int i = 0; i < operands.Count; i++)
            {
                if (operands[i].Enum != null && operands[i].Enum!.Count > 0)
                {
                    enumValues = operands[i].Enum;
                    break;
                }
            }

            if (enumValues == null)
            {
                // Fallback: single generic constructor
                sb.AppendLine($":{name} reg4 is op12=0x{op12Value:X3} & reg4 {{");
                sb.AppendLine($"    # {name}: no enum data available");
                sb.AppendLine("}");
                return;
            }

            string displayField = name == "TRA" ? "tra_reg" : "trr_reg";
            string prefix = name == "TRA" ? "read" : "write";

            // Generate one constructor per known register value
            for (int i = 0; i < enumValues.Count; i++)
            {
                var opt = enumValues[i];
                // Parse octal value string to decimal
                int regValue = Convert.ToInt32(opt.Value, 8);
                string regName = opt.Name;

                sb.AppendLine();
                sb.AppendLine($":{name} {displayField} is op12=0x{op12Value:X3} & {displayField} & reg4=0x{regValue:X} {{  # {name} {regName} ({opt.Value} octal)");

                if (name == "TRA")
                {
                    sb.AppendLine($"    A = {prefix}_{regName}();");
                }
                else
                {
                    sb.AppendLine($"    {prefix}_{regName}(A);");
                }

                sb.AppendLine("}");
            }

            // Fallback constructor for undefined register values
            sb.AppendLine();
            sb.AppendLine($":{name} {displayField} is op12=0x{op12Value:X3} & {displayField} & reg4 {{  # {name} (unknown register)");
            if (name == "TRA")
            {
                sb.AppendLine("    local regsel:1 = reg4;");
                sb.AppendLine("    A = nd100_tra(regsel);");
            }
            else
            {
                sb.AppendLine("    local regsel:1 = reg4;");
                sb.AppendLine("    nd100_trr(regsel, A);");
            }
            sb.AppendLine("}");
        }

        /// <summary>
        /// One constructor per SINTRAN monitor call that has more than one return
        /// (nd100-definitions specs/mon-calls.json, "exits"): the error return at +1 and the
        /// normal (skip) return at +2, CopyPage also +3. The CPU itself only traps
        /// (nd100x opcode_mon_monitor_call leaves P at the next word); SINTRAN moves the saved P.
        /// </summary>
        private string GenerateMonReturnConstructors()
        {
            string jsonPath = Path.Combine(BaseDirectory, "nd100-definitions", "specs", "mon-calls.json");
            var spec = System.Text.Json.JsonSerializer.Deserialize<NDGen.Core.Models.MonCallSpec>(File.ReadAllText(jsonPath))
                ?? throw new InvalidOperationException("Failed to read mon-calls.json");
            var sb = new StringBuilder();
            string[] labels = { "skip_err", "skip_ok", "skip_ok2" };
            for (int i = 0; i < spec.MonCalls.Count; i++)
            {
                var call = spec.MonCalls[i];
                int n = call.Exits.Count;
                if (n < 2)
                    continue;
                for (int k = 0; k < n; k++)
                {
                    if (call.Exits[k].Offset != k + 1)
                        throw new InvalidOperationException($"mon-calls.json: {call.Name} exit {k} is not at +{k + 1}");
                }
                if (n > labels.Length)
                    throw new InvalidOperationException($"mon-calls.json: {call.Name} has {n} exits");
                string ops = string.Join(", ", labels, 0, n);
                string seq = string.Join(" ; ", labels, 0, n);
                sb.AppendLine($"# MON {call.Octal} {call.Name}: {n} returns ({call.ExitsSource})");
                // The call number is fixed here, so it is printed as text (SLEIGH does not take a
                // field as an operand in a constructor that fixes its value), in the same "0x.."
                // form as the general MON.
                sb.AppendLine($":MON \"0x{call.Decimal:x}\" {ops} is op8=0xD6 & imm8=0x{call.Decimal:X2} ; {seq} {{");
                sb.AppendLine($"    local mon_code:1 = 0x{call.Decimal:X2};");
                sb.AppendLine("    nd100_mon(mon_code);");
                if (n == 2)
                {
                    // Asked as "did the call fail?", so the decompiler shows the error return as
                    // "if (nd100_mon_error(n)) { ... }", the way ADDD shows nd100_error_return().
                    sb.AppendLine("    local failed:1 = nd100_mon_error(mon_code);");
                    sb.AppendLine("    if (failed != 0) goto skip_err;");
                    sb.AppendLine("    goto skip_ok;");
                }
                else
                {
                    // CopyPage: destination error, source error, normal. Asked one question per
                    // error return.
                    sb.AppendLine("    local destErr:1 = nd100_mon_error(mon_code);");
                    sb.AppendLine("    if (destErr != 0) goto skip_err;");
                    sb.AppendLine("    local srcErr:1 = nd100_mon_error2(mon_code);");
                    sb.AppendLine("    if (srcErr != 0) goto skip_ok;");
                    sb.AppendLine("    goto skip_ok2;");
                }
                sb.AppendLine("}");
            }
            return sb.ToString();
        }

        // P-code is loaded from .sinc files in src/NDGen.Generators.Ghidra/Ghidra/Templates/p-codes/
        // To add or fix P-code for an instruction, edit its .sinc file directly.

        /// <summary>
        /// Loads a full constructor .sinc file (contains complete constructor definitions including headers).
        /// Used for instructions like JMP/JPL that need multiple constructors per instruction.
        /// Returns the file contents if it starts with ':' or '#' (full constructor), null otherwise.
        /// </summary>
        private string? LoadFullConstructor(string instructionName)
        {
            var templatesDir = Path.Combine(BaseDirectory, "src", "NDGen.Generators.Ghidra", "Ghidra", "Templates", "p-codes");
            var templatePath = Path.Combine(templatesDir, $"{instructionName}.sinc");

            if (!File.Exists(templatePath))
                return null;

            var content = File.ReadAllText(templatePath);
            // Full constructor files contain lines starting with ':' (constructor definitions)
            if (content.StartsWith(":") || content.Contains("\n:"))
                return content;

            return null;
        }

        /// <summary>
        /// Loads P-code body from a .sinc file in the p-codes/ template directory.
        /// The .sinc files contain only the P-code body lines (no constructor header).
        /// Returns the file contents, or null if no file exists.
        /// </summary>
        private string? LoadPCodeBody(string instructionName)
        {
            var templatesDir = Path.Combine(BaseDirectory, "src", "NDGen.Generators.Ghidra", "Ghidra", "Templates", "p-codes");
            var templatePath = Path.Combine(templatesDir, $"{instructionName}.sinc");

            if (!File.Exists(templatePath))
                return null;

            return File.ReadAllText(templatePath);
        }

        private void CopyTemplateFiles()
        {
            var templatesDir = Path.Combine(BaseDirectory, "src", "NDGen.Generators.Ghidra", "Ghidra", "Templates");
            
            // Process pspec template — inject generated I/O device symbols
            var ioDevGen = new GhidraIODeviceGenerator(BaseDirectory, OutputPath);
            string pspecContent = File.ReadAllText(Path.Combine(templatesDir, "nd100.pspec"));
            string ioSymbols = ioDevGen.GeneratePspecSymbols();
            pspecContent = pspecContent.Replace("    <!-- {{GENERATED_IO_SYMBOLS}} -->", ioSymbols);
            File.WriteAllText(Path.Combine(_languagesPath, "nd100.pspec"), pspecContent);
                      
            File.Copy(Path.Combine(templatesDir, "nd100.cspec"), 
                      Path.Combine(_languagesPath, "nd100.cspec"), overwrite: true);
                      
            File.Copy(Path.Combine(templatesDir, "nd100.ldefs"), 
                      Path.Combine(_languagesPath, "nd100.ldefs"), overwrite: true);
                      
            File.Copy(Path.Combine(templatesDir, "nd100.opinion"), 
                      Path.Combine(_languagesPath, "nd100.opinion"), overwrite: true);
            
            // Copy SLEIGH include files
            File.Copy(Path.Combine(templatesDir, "nd100_registers.sinc"),
                      Path.Combine(_languagesPath, "nd100_registers.sinc"), overwrite: true);

            File.Copy(Path.Combine(templatesDir, "nd100_memory.sinc"),
                      Path.Combine(_languagesPath, "nd100_memory.sinc"), overwrite: true);

            File.Copy(Path.Combine(templatesDir, "nd100_shift.sinc"),
                      Path.Combine(_languagesPath, "nd100_shift.sinc"), overwrite: true);

            File.Copy(Path.Combine(templatesDir, "nd100.sinc"),
                      Path.Combine(_languagesPath, "nd100.sinc"), overwrite: true);

            // Copy all manual P-code template files
            var pcodesDir = Path.Combine(templatesDir, "p-codes");
            var pcodesOutputDir = Path.Combine(_languagesPath, "p-codes");
            Directory.CreateDirectory(pcodesOutputDir);

            // Copy all .sinc files from p-codes templates directory
            if (Directory.Exists(pcodesDir))
            {
                var templateFiles = Directory.GetFiles(pcodesDir, "*.sinc");
                foreach (var templateFile in templateFiles)
                {
                    var fileName = Path.GetFileName(templateFile);
                    var outputPath = Path.Combine(pcodesOutputDir, fileName);
                    File.Copy(templateFile, outputPath, overwrite: true);
                }
                Console.WriteLine($"✓ Copied {templateFiles.Length} manual P-code template files");
            }
        }

        /// <summary>
        /// Builds a complete Ghidra extension with SLEIGH compilation and ZIP packaging.
        /// </summary>
        /// <param name="ghidraInstallPath">Path to Ghidra installation. If null/empty, falls back to the
        /// GHIDRA_INSTALL_DIR environment variable.</param>
        /// <param name="version">Extension version (e.g., "11.4")</param>
        /// <returns>Path to created extension ZIP file</returns>
        public string BuildCompleteExtension(string? ghidraInstallPath = null, string version = "12.0")
        {
            if (string.IsNullOrWhiteSpace(ghidraInstallPath))
            {
                ghidraInstallPath = Environment.GetEnvironmentVariable("GHIDRA_INSTALL_DIR");
            }
            if (string.IsNullOrWhiteSpace(ghidraInstallPath))
            {
                throw new InvalidOperationException(
                    "Ghidra install path not provided and GHIDRA_INSTALL_DIR is not set.");
            }
            Console.WriteLine("=== Building Complete ND-100 Ghidra Extension ===");

            // The Ghidra version is taken from the install we build against, never written
            // into the code. It names the zip and goes into extension.properties, and Ghidra
            // refuses to install an extension whose version does not match its own.
            _ghidraVersion = ReadGhidraVersion(ghidraInstallPath);
            Console.WriteLine($"✓ Building against Ghidra {_ghidraVersion} ({ghidraInstallPath})");

            // Step 1: Generate SLEIGH files (already done by Generate())
            Console.WriteLine("✓ SLEIGH files generated");

            // Step 2: Create extension directory structure
            var extensionRoot = CreateExtensionStructure(version);
            Console.WriteLine($"✓ Extension structure created at: {extensionRoot}");

            // Step 3: Compile SLEIGH specification
            CompileSleighSpecification(ghidraInstallPath);
            Console.WriteLine("✓ SLEIGH specification compiled");

            // Step 4: Copy BPUN loader (if exists)
            CopyBpunLoader(extensionRoot);

            // Step 5: Create extension ZIP
            var zipPath = CreateExtensionZip(extensionRoot);
            Console.WriteLine($"✓ Extension ZIP created: {zipPath}");

            return zipPath;
        }

        /// <summary>Ghidra version of the install being built against (e.g. "12.2"), set by BuildCompleteExtension.</summary>
        private string _ghidraVersion = string.Empty;

        /// <summary>
        /// Reads <c>application.version</c> from <c>&lt;install&gt;/Ghidra/application.properties</c>.
        /// </summary>
        /// <param name="ghidraInstallPath">Root of the Ghidra installation.</param>
        /// <returns>The Ghidra version string, for example "12.2".</returns>
        /// <exception cref="FileNotFoundException">The install has no application.properties.</exception>
        /// <exception cref="InvalidOperationException">The file has no application.version line.</exception>
        private static string ReadGhidraVersion(string ghidraInstallPath)
        {
            var propsPath = Path.Combine(ghidraInstallPath, "Ghidra", "application.properties");
            if (!File.Exists(propsPath))
            {
                throw new FileNotFoundException($"Not a Ghidra install (no application.properties): {propsPath}");
            }

            const string key = "application.version=";
            var lines = File.ReadAllLines(propsPath);
            for (int i = 0; i < lines.Length; i++)
            {
                var line = lines[i].Trim();
                if (line.StartsWith(key, StringComparison.Ordinal))
                {
                    return line.Substring(key.Length).Trim();
                }
            }

            throw new InvalidOperationException($"No application.version in {propsPath}");
        }

        private string CreateExtensionStructure(string version)
        {
            // Create the proper extension structure on disk with ND-100 as the root
            var extensionRoot = Path.Combine(_outputPath, "ND-100");
            var libDir = Path.Combine(extensionRoot, "lib");
            
            // Create standard Ghidra extension directories (following skeleton template)
            Directory.CreateDirectory(libDir);
            Directory.CreateDirectory(Path.Combine(extensionRoot, "src", "main", "java"));
            Directory.CreateDirectory(Path.Combine(extensionRoot, "src", "main", "resources"));
            Directory.CreateDirectory(Path.Combine(extensionRoot, "src", "main", "help"));
            Directory.CreateDirectory(Path.Combine(extensionRoot, "ghidra_scripts"));
            Directory.CreateDirectory(Path.Combine(extensionRoot, "os"));

            // Create extension.properties using template
            var templatesDirPath = Path.Combine(BaseDirectory, "src", "NDGen.Generators.Ghidra", "Ghidra", "Templates");
            var extensionPropsTemplate = Path.Combine(templatesDirPath, "extension.properties");
            var extensionProps = Path.Combine(extensionRoot, "extension.properties");
            
            var templateContent = File.ReadAllText(extensionPropsTemplate)
                .Replace("@name@", "ND-100")
                .Replace("@description@", "ND-100 processor language specification with SLEIGH disassembler and BPUN file format loader")
                .Replace("@author@", "Ronny Hansen")
                .Replace("@createdOn@", DateTime.Now.ToString("MM/dd/yyyy"))
                .Replace("@version@", _ghidraVersion);
            
            File.WriteAllText(extensionProps, templateContent);

            // Create Module.manifest using XML template
            var moduleManifest = Path.Combine(extensionRoot, "Module.manifest");
            var manifestTemplate = Path.Combine(BaseDirectory, "src", "NDGen.Generators.Ghidra", "Ghidra", "Templates", "Module.manifest");
            var manifestContent = File.ReadAllText(manifestTemplate)
                .Replace("@buildDate@", DateTime.Now.ToString("yyyy-MM-dd"));
            File.WriteAllText(moduleManifest, manifestContent);

            // Copy README.md template (following official extension standards)
            var templatesDir = Path.Combine(BaseDirectory, "src", "NDGen.Generators.Ghidra", "Ghidra", "Templates");
            var readmeTemplate = Path.Combine(templatesDir, "README.md");
            var readmeTarget = Path.Combine(extensionRoot, "README.md");
            
            if (File.Exists(readmeTemplate))
            {
                File.Copy(readmeTemplate, readmeTarget, overwrite: true);
            }
            else
            {
                // Create a basic README if template is missing
                File.WriteAllText(readmeTarget, @"# ND-100 Ghidra Extension

This extension provides complete ND-100 processor support for Ghidra, including:
- SLEIGH language specification with 153 instructions
- BPUN (Bootable Punched Tape) file format loader
- Modern Ghidra loader API implementation

## Installation
Install via Ghidra's File → Install Extensions menu.

## Language ID
ND-100:BE:16:default
");
            }

            return extensionRoot;
        }

        private void CompileSleighSpecification(string ghidraInstallPath)
        {
            // Pick the platform-appropriate sleigh launcher: `sleigh.bat` on Windows,
            // bare `sleigh` (the shell wrapper) elsewhere.
            var sleighName = OperatingSystem.IsWindows() ? "sleigh.bat" : "sleigh";
            var sleighCompiler = Path.Combine(ghidraInstallPath, "support", sleighName);
            var slaspecPath = Path.Combine(_languagesPath, "nd100.slaspec");

            if (!File.Exists(sleighCompiler))
            {
                throw new FileNotFoundException($"SLEIGH compiler not found: {sleighCompiler}");
            }

            if (!File.Exists(slaspecPath))
            {
                throw new FileNotFoundException($"SLASPEC file not found: {slaspecPath}");
            }

            var processInfo = new ProcessStartInfo
            {
                FileName = sleighCompiler,
                Arguments = $"-n -t \"{slaspecPath}\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            Console.WriteLine($"Running: {processInfo.FileName} {processInfo.Arguments}");

            using (var process = Process.Start(processInfo))
            {
                if (process == null)
                    throw new InvalidOperationException("Failed to start SLEIGH compiler process.");

                var output = process.StandardOutput.ReadToEnd();
                var error = process.StandardError.ReadToEnd();

                process.WaitForExit();

                // Display warnings (expected for NOP constructors and unused temporaries)
                if (!string.IsNullOrEmpty(output))
                {
                    Console.WriteLine("SLEIGH Compiler Output:");
                    Console.WriteLine(output);
                }

                if (!string.IsNullOrEmpty(error))
                {
                    Console.WriteLine("SLEIGH Compiler Warnings/Errors:");
                    Console.WriteLine(error);
                }

                if (process.ExitCode != 0)
                {
                    throw new InvalidOperationException($"SLEIGH compilation failed with exit code {process.ExitCode}");
                }

                // Verify .sla file was created
                var slaPath = Path.Combine(_languagesPath, "nd100.sla");
                if (!File.Exists(slaPath))
                {
                    throw new InvalidOperationException("SLEIGH compilation did not produce nd100.sla file");
                }

                Console.WriteLine($"✓ SLEIGH compilation successful, created: {slaPath}");
            }
        }

        private void CopyBpunLoader(string extensionRoot)
        {
            // JAR is built by Gradle in deploy-to-ghidra.bat as ND-100.jar
            // Do NOT copy a pre-built JAR here — it would create a stale duplicate
            Console.WriteLine("  BPUN loader JAR will be built by Gradle in deploy-to-ghidra.bat");
        }

        private bool VerifyGradleJarContainsSpiServices(string jarPath)
        {
            try
            {
                using var archive = System.IO.Compression.ZipFile.OpenRead(jarPath);
                return archive.Entries.Any(entry => entry.FullName == "META-INF/services/ghidra.app.util.opinion.Loader");
            }
            catch
            {
                return false;
            }
        }


        private void CopyDirectory(string sourceDir, string destDir)
        {
            Directory.CreateDirectory(destDir);
            
            // Copy all files
            foreach (var file in Directory.GetFiles(sourceDir, "*", SearchOption.AllDirectories))
            {
                var relativePath = Path.GetRelativePath(sourceDir, file);
                var destFile = Path.Combine(destDir, relativePath);
                Directory.CreateDirectory(Path.GetDirectoryName(destFile)!);
                File.Copy(file, destFile, true);
            }
        }

        private string CreateExtensionZip(string extensionRoot)
        {
            var dateStr = DateTime.Now.ToString("yyyyMMdd");
            var zipName = $"ghidra_{_ghidraVersion}_PUBLIC_{dateStr}_ND-100.zip";
            var zipPath = Path.Combine(_outputPath, zipName);

            Console.WriteLine($"Creating extension ZIP: {zipPath}");
            Console.WriteLine($"From directory: {extensionRoot}");

            // ZIP the ND-100 directory contents with ND-100 as root
            BuildGhidraExtensionZipWithRoot(extensionRoot, zipPath, "ND-100");

            // Verify ZIP contents after ensuring file is closed
            if (File.Exists(zipPath))
            {
                Console.WriteLine("ZIP contents:");
                using (var archive = ZipFile.OpenRead(zipPath))
                {
                    foreach (var entry in archive.Entries)
                    {
                        Console.WriteLine($"  {entry.FullName}");
                    }
                }
            }

            return zipPath;
        }

        private void BuildGhidraExtensionZipWithRoot(string sourceDir, string zipPath, string topFolderName)
        {
            if (!Directory.Exists(sourceDir))
                throw new DirectoryNotFoundException(sourceDir);

            Console.WriteLine($"DEBUG: Source directory: {sourceDir}");
            Console.WriteLine($"DEBUG: ZIP path: {zipPath}");
            Console.WriteLine($"DEBUG: Top folder name: {topFolderName}");

            if (File.Exists(zipPath)) 
            {
                Console.WriteLine("DEBUG: Deleting existing ZIP file");
                File.Delete(zipPath);
            }

            Console.WriteLine("DEBUG: Creating ZIP archive");
            using (var fs = new FileStream(zipPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            using (var zip = new ZipArchive(fs, ZipArchiveMode.Create, leaveOpen: false, entryNameEncoding: System.Text.Encoding.UTF8))
            {
                Console.WriteLine("DEBUG: ZIP archive created");
                
                // Clear directory tracking for this ZIP
                _addedDirectories.Clear();

                // 1) Add top-level directory entry first
                Console.WriteLine("DEBUG: Adding top-level directory entry");
                AddDirectoryEntry(zip, topFolderName);

            // 2) Add subdirectories (ensure dir entries exist)
            foreach (var dir in Directory.EnumerateDirectories(sourceDir, "*", SearchOption.AllDirectories)
                                         .OrderBy(p => p.Length))
            {
                var relDir = Path.GetRelativePath(sourceDir, dir);
                if (IsUnderFolder(relDir, "build") || IsUnderFolder(relDir, "dist"))
                {
                    continue; // Gradle output, see the file loop below
                }
                var rel = topFolderName + "/" + ToZipPath(relDir);
                AddDirectoryEntry(zip, rel);
            }

            // 3) Add files
            foreach (var file in Directory.EnumerateFiles(sourceDir, "*", SearchOption.AllDirectories)
                                          .OrderBy(p => p.Length))
            {
                var relativePath = Path.GetRelativePath(sourceDir, file);

                // Skip Gradle's own output folders. ND-100/build holds temporary build files and
                // ND-100/dist holds earlier extension zips; without this skip every old zip was
                // packed inside the new one.
                if (IsUnderFolder(relativePath, "build") || IsUnderFolder(relativePath, "dist"))
                {
                    continue;
                }

                // Skip META-INF directories and files
                if (relativePath.StartsWith("META-INF", StringComparison.OrdinalIgnoreCase) ||
                    relativePath.Contains("\\META-INF\\", StringComparison.OrdinalIgnoreCase) ||
                    relativePath.Contains("/META-INF/", StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine($"  Skipping META-INF: {relativePath}");
                    continue;
                }

                var rel = topFolderName + "/" + ToZipPath(relativePath);
                AddFileEntry(zip, file, rel);
            }
            } // Close the using statements
        }

        /// <summary>
        /// True when a path relative to the extension root is the top-level folder
        /// <paramref name="folder"/> or lies inside it.
        /// </summary>
        private static bool IsUnderFolder(string relativePath, string folder)
        {
            if (relativePath.Equals(folder, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
            return relativePath.StartsWith(folder + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
                || relativePath.StartsWith(folder + Path.AltDirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
        }

        private HashSet<string> _addedDirectories = new HashSet<string>();

        private void AddDirectoryEntry(ZipArchive zip, string relPath)
        {
            if (string.IsNullOrWhiteSpace(relPath)) return;
            var name = relPath.EndsWith("/") ? relPath : relPath + "/";
            
            // Avoid duplicate dir entries using our own tracking
            if (_addedDirectories.Contains(name)) return;
            _addedDirectories.Add(name);
            
            var entry = zip.CreateEntry(name); // zero-length entry marking a directory
            entry.LastWriteTime = DateTimeOffset.UtcNow;
        }

        private void AddFileEntry(ZipArchive zip, string sourceFile, string relPath)
        {
            // Normalize separator to forward slash
            var entryName = relPath.Replace('\\', '/');
            var entry = zip.CreateEntry(entryName, CompressionLevel.Optimal);
            entry.LastWriteTime = File.GetLastWriteTimeUtc(sourceFile);

            Console.WriteLine($"  Adding: {entryName}");

            using var src = new FileStream(sourceFile, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var dst = entry.Open();
            src.CopyTo(dst);
        }

        private string ToZipPath(string path) => path.Replace('\\', '/');

        /// <summary>
        /// Convenience method to build extension with default settings
        /// </summary>
        public string BuildExtension()
        {
            return BuildCompleteExtension();
        }
    }
}