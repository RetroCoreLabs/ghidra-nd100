using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using NDGen.Core;
using NDGen.Core.Models;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;

namespace NDGen.Generators.Ghidra
{
    /// <summary>
    /// Generates a PDF processor manual and Ghidra .idx index file for the ND-100.
    /// Two-pass approach:
    ///   Pass 1: Generate PDF with instructions first, then appendix (title/TOC)
    ///   Pass 2: Count actual PDF pages and compute correct .idx page numbers
    /// </summary>
    public class GhidraManualGenerator
    {
        private readonly string _outputPath;
        private readonly DefinitionLoader _loader;

        // Everything printed about an instruction comes from nd100-definitions: the manual titles
        // and the privilege wording from cpu.yaml, the groups from categories.yaml.
        private readonly Dictionary<string, string> _manualTitles = new(StringComparer.Ordinal);
        private readonly Dictionary<string, string> _privilegeText = new(StringComparer.OrdinalIgnoreCase);

        public GhidraManualGenerator(string outputPath, DefinitionLoader loader)
        {
            _outputPath = outputPath;
            _loader = loader;
        }

        public string Generate()
        {
            QuestPDF.Settings.License = LicenseType.Community;

            var manualsDir = Path.Combine(_outputPath, "ND-100", "data", "manuals");
            Directory.CreateDirectory(manualsDir);

            var pdfPath = Path.Combine(manualsDir, "nd100_manual.pdf");
            var idxPath = Path.Combine(manualsDir, "nd100.idx");

            var instructions = _loader.GetInstructions();
            var cpuDef = _loader.GetCpuDefinition();

            var manuals = cpuDef.Metadata.Manuals;
            for (int m = 0; m < manuals.Count; m++)
                _manualTitles[manuals[m].Id] = manuals[m].Title;
            var levels = cpuDef.Metadata.PrivilegeLevels;
            for (int l = 0; l < levels.Count; l++)
                _privilegeText[levels[l].Name] = levels[l].Description;

            // Sort instructions alphabetically
            var sorted = new List<InstructionDefinition>(instructions);
            sorted.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.Ordinal));

            // Pass 1: Generate individual PDFs per instruction to find exact page counts
            var pageCounts = new int[sorted.Count];
            for (int i = 0; i < sorted.Count; i++)
            {
                var instr = sorted[i];
                var singleDoc = Document.Create(c => GenerateInstructionPage(c, instr));
                var bytes = singleDoc.GeneratePdf();
                pageCounts[i] = CountPdfPages(bytes);
            }

            // Compute page mapping: instruction i starts at page = sum of all previous page counts + 1
            var pageStarts = new int[sorted.Count];
            int currentPage = 1;
            for (int i = 0; i < sorted.Count; i++)
            {
                pageStarts[i] = currentPage;
                currentPage += pageCounts[i];
            }

            // Pass 2: Generate the final combined PDF
            var document = Document.Create(container =>
            {
                // Instruction pages first
                for (int i = 0; i < sorted.Count; i++)
                {
                    GenerateInstructionPage(container, sorted[i]);
                }

                // Appendix: title page
                GenerateTitlePage(container, sorted, cpuDef);

                // Appendix: TOC with correct page numbers
                GenerateTocPage(container, sorted, pageStarts);

                // Appendix: the instruction groups (categories.yaml). After the TOC, so they never
                // move an instruction page and the .idx page numbers stay right.
                GenerateCategoryPages(container, sorted, pageStarts);
            });

            document.GeneratePdf(pdfPath);

            // Generate .idx with correct page numbers
            GenerateIndexFile(idxPath, sorted, pageStarts);

            return idxPath;
        }

        /// <summary>"ND-110 Instruction Set (ND-06.029.1), page 85" from one manual reference.</summary>
        private string DescribeRef(ManualRef r)
        {
            var title = _manualTitles.TryGetValue(r.Manual, out var t) ? $"{t} ({r.Manual})" : r.Manual;
            if (r.Page.HasValue) return $"{title}, page {r.Page.Value}";
            if (!string.IsNullOrEmpty(r.Pages))
                return r.Pages.Contains('-') ? $"{title}, pages {r.Pages}" : $"{title}, page {r.Pages}";
            if (!string.IsNullOrEmpty(r.Section)) return $"{title}, section {r.Section}";
            return title;
        }

        private static void Section(ColumnDescriptor col, string title, string? text)
        {
            if (string.IsNullOrEmpty(text)) return;
            col.Item().PaddingTop(10).Text(title).FontSize(11).Bold();
            Body(col, text, 9);
        }

        /// <summary>
        /// Text from the definitions. Lines inside &lt;ascii-table&gt; ... &lt;/ascii-table&gt;
        /// and lines indented by four or more spaces are drawn tables, formulas and bit layouts:
        /// they go in a fixed-width font so their columns line up, and the markers are dropped.
        /// Everything else is ordinary text.
        /// </summary>
        private static void Body(ColumnDescriptor col, string text, float size)
        {
            var lines = text.Replace("\r\n", "\n").Trim('\n').Split('\n');
            var block = new StringBuilder();
            bool mono = false;
            bool inTable = false;
            void Flush()
            {
                if (block.Length == 0) return;
                var t = block.ToString().TrimEnd('\n');
                if (t.Trim().Length > 0)
                {
                    if (mono)
                        col.Item().PaddingTop(3).Text(t).FontSize(size - 1).FontFamily(Fonts.CourierNew);
                    else
                        col.Item().PaddingTop(3).Text(t.Trim()).FontSize(size);
                }
                block.Clear();
            }
            for (int i = 0; i < lines.Length; i++)
            {
                var line = lines[i].TrimEnd();
                var trimmed = line.Trim();
                if (trimmed == "<ascii-table>") { Flush(); inTable = true; mono = true; continue; }
                if (trimmed == "</ascii-table>") { Flush(); inTable = false; mono = false; continue; }
                // Markdown emphasis and code marks mean nothing in the PDF; drop them.
                line = line.Replace("**", "").Replace("`", "");
                bool lineMono = inTable || line.StartsWith("    ", StringComparison.Ordinal)
                    || line.TrimStart().StartsWith("|", StringComparison.Ordinal);
                if (line.Length > 0 && lineMono != mono) { Flush(); mono = lineMono; }
                block.Append(line).Append('\n');
            }
            Flush();
        }

        private void GenerateInstructionPage(IDocumentContainer container, InstructionDefinition instr)
        {
            container.Page(page =>
            {
                page.Size(PageSizes.A4);
                page.MarginHorizontal(50);
                page.MarginVertical(40);

                page.Header().BorderBottom(1).BorderColor(Colors.Grey.Lighten2).PaddingBottom(5).Row(row =>
                {
                    row.RelativeItem().Text(instr.Name).FontSize(10).Bold();
                    row.ConstantItem(200).AlignRight().Text(instr.Category ?? "").FontSize(8).FontColor(Colors.Grey.Darken1);
                });

                page.Content().PaddingTop(10).Column(col =>
                {
                    col.Item().Text(instr.Name).FontSize(26).Bold();
                    Body(col, instr.Description ?? "", 11);

                    // Info box
                    col.Item().PaddingTop(12).Background(Colors.Grey.Lighten4).Padding(8).Column(info =>
                    {
                        info.Item().Row(row =>
                        {
                            row.ConstantItem(90).Text("Opcode:").FontSize(9).Bold();
                            row.RelativeItem().Text($"{instr.Opcode} (octal) = 0x{instr.OpcodeValue:X4}").FontSize(9).FontFamily(Fonts.CourierNew);
                        });
                        info.Item().PaddingTop(2).Row(row =>
                        {
                            row.ConstantItem(90).Text("Format:").FontSize(9).Bold();
                            row.RelativeItem().Text(instr.Format ?? "").FontSize(9).FontFamily(Fonts.CourierNew);
                        });
                        if (!string.IsNullOrEmpty(instr.Mask))
                        {
                            info.Item().PaddingTop(2).Row(row =>
                            {
                                row.ConstantItem(90).Text("Mask:").FontSize(9).Bold();
                                row.RelativeItem().Text(instr.Mask).FontSize(9).FontFamily(Fonts.CourierNew);
                            });
                        }
                        info.Item().PaddingTop(2).Row(row =>
                        {
                            row.ConstantItem(90).Text("Privilege:").FontSize(9).Bold();
                            var level = instr.Privilege.ToString().ToLowerInvariant();
                            var meaning = _privilegeText.TryGetValue(level, out var pt) ? $"{level}: {pt}" : level;
                            row.RelativeItem().Text(meaning).FontSize(9);
                        });
                        info.Item().PaddingTop(2).Row(row =>
                        {
                            row.ConstantItem(90).Text("Category:").FontSize(9).Bold();
                            row.RelativeItem().Text(instr.Category ?? "").FontSize(9);
                        });
                        for (int r = 0; r < instr.ManualRefs.Count; r++)
                        {
                            var refText = DescribeRef(instr.ManualRefs[r]);
                            info.Item().PaddingTop(2).Row(row =>
                            {
                                row.ConstantItem(90).Text("Manual:").FontSize(9).Bold();
                                row.RelativeItem().Text(refText).FontSize(9);
                            });
                        }
                        if (!string.IsNullOrEmpty(instr.InstructionClass))
                        {
                            info.Item().PaddingTop(2).Row(row =>
                            {
                                row.ConstantItem(90).Text("Class:").FontSize(9).Bold();
                                row.RelativeItem().Text(instr.InstructionClass.Replace('_', ' ')).FontSize(9);
                            });
                        }
                    });

                    // Bit format
                    if (!string.IsNullOrEmpty(instr.GeneratedBitFormat))
                    {
                        col.Item().PaddingTop(10).Text("Bit Format").FontSize(11).Bold();
                        col.Item().PaddingTop(3).Text(instr.GeneratedBitFormat).FontSize(8).FontFamily(Fonts.CourierNew);
                    }

                    // Detailed description, and the two further text fields of the definitions
                    Section(col, "Description", instr.DetailedDescription);
                    Section(col, "More", instr.ExtendedDescription);
                    Section(col, "Before use", instr.BeforeUse);

                    // Operands
                    if (instr.Operands != null && instr.Operands.Count > 0)
                    {
                        col.Item().PaddingTop(10).Text("Operands").FontSize(11).Bold();
                        col.Item().PaddingTop(3).Table(table =>
                        {
                            table.ColumnsDefinition(cols =>
                            {
                                cols.ConstantColumn(90);
                                cols.ConstantColumn(55);
                                cols.ConstantColumn(75);
                                cols.RelativeColumn();
                            });

                            table.Header(header =>
                            {
                                header.Cell().Background(Colors.Grey.Lighten3).Padding(2).Text("Name").FontSize(8).Bold();
                                header.Cell().Background(Colors.Grey.Lighten3).Padding(2).Text("Bits").FontSize(8).Bold();
                                header.Cell().Background(Colors.Grey.Lighten3).Padding(2).Text("Type").FontSize(8).Bold();
                                header.Cell().Background(Colors.Grey.Lighten3).Padding(2).Text("Description").FontSize(8).Bold();
                            });

                            for (int o = 0; o < instr.Operands.Count; o++)
                            {
                                var op = instr.Operands[o];
                                var bg = o % 2 == 0 ? Colors.White : Colors.Grey.Lighten5;
                                table.Cell().Background(bg).Padding(2).Text(op.Name).FontSize(8);
                                table.Cell().Background(bg).Padding(2).Text(op.Bits).FontSize(8);
                                table.Cell().Background(bg).Padding(2).Text(op.Type ?? "").FontSize(8);
                                table.Cell().Background(bg).Padding(2).Text(op.Description ?? "").FontSize(8);
                            }
                        });

                        // The values a field can take (for example the eight SKP conditions)
                        for (int o = 0; o < instr.Operands.Count; o++)
                        {
                            var op = instr.Operands[o];
                            if (op.Enum == null || op.Enum.Count == 0) continue;
                            col.Item().PaddingTop(6).Text($"Values of {op.Name} (octal)").FontSize(9).Bold();
                            col.Item().PaddingTop(2).Table(table =>
                            {
                                table.ColumnsDefinition(cols =>
                                {
                                    cols.ConstantColumn(45);
                                    cols.ConstantColumn(70);
                                    cols.RelativeColumn();
                                });
                                for (int e = 0; e < op.Enum.Count; e++)
                                {
                                    var v = op.Enum[e];
                                    var bg = e % 2 == 0 ? Colors.White : Colors.Grey.Lighten5;
                                    table.Cell().Background(bg).Padding(2).Text(v.Value).FontSize(8).FontFamily(Fonts.CourierNew);
                                    table.Cell().Background(bg).Padding(2).Text(v.Name).FontSize(8).Bold();
                                    table.Cell().Background(bg).Padding(2).Text(v.Description ?? "").FontSize(8);
                                }
                            });
                        }
                    }

                    // Flags
                    if (instr.FlagsAffected != null && instr.FlagsAffected.Count > 0)
                    {
                        var flagStr = new StringBuilder();
                        for (int f = 0; f < instr.FlagsAffected.Count; f++)
                        {
                            if (f > 0) flagStr.Append(", ");
                            flagStr.Append(instr.FlagsAffected[f]);
                        }
                        col.Item().PaddingTop(10).Text($"Flags: {flagStr}").FontSize(9).Bold();

                        if (instr.Flags != null)
                        {
                            var details = new StringBuilder();
                            AppendFlag(details, "C", instr.Flags.C);
                            AppendFlag(details, "O", instr.Flags.O);
                            AppendFlag(details, "Q", instr.Flags.Q);
                            AppendFlag(details, "Z", instr.Flags.Z);
                            if (details.Length > 0)
                                col.Item().PaddingTop(2).Text(details.ToString()).FontSize(8);
                        }
                    }

                    // Where execution continues (exits)
                    if (instr.Exits != null && instr.Exits.Count > 0)
                    {
                        col.Item().PaddingTop(10).Text("Where execution continues").FontSize(11).Bold();
                        col.Item().PaddingTop(3).Table(table =>
                        {
                            table.ColumnsDefinition(cols =>
                            {
                                cols.ConstantColumn(150);
                                cols.ConstantColumn(60);
                                cols.RelativeColumn();
                            });
                            for (int x = 0; x < instr.Exits.Count; x++)
                            {
                                var ex = instr.Exits[x];
                                var at = ex.Offset.HasValue
                                    ? (ex.Offset.Value == 1 ? "the next word" : $"{ex.Offset.Value} words on")
                                    : (ex.Target ?? "").Replace('_', ' ');
                                var bg = x % 2 == 0 ? Colors.White : Colors.Grey.Lighten5;
                                table.Cell().Background(bg).Padding(2).Text(at).FontSize(8);
                                table.Cell().Background(bg).Padding(2).Text(ex.When ?? "").FontSize(8);
                                table.Cell().Background(bg).Padding(2).Text(ex.Condition ?? "").FontSize(8);
                            }
                        });
                    }

                    // Pseudocode
                    if (!string.IsNullOrEmpty(instr.Pseudocode))
                    {
                        col.Item().PaddingTop(10).Text("Pseudocode").FontSize(11).Bold();
                        col.Item().PaddingTop(3).Background(Colors.Grey.Lighten4).Padding(6)
                            .Text(instr.Pseudocode).FontSize(8).FontFamily(Fonts.CourierNew);
                    }

                    // Examples
                    if (instr.Examples != null && instr.Examples.Count > 0)
                    {
                        col.Item().PaddingTop(10).Text("Examples").FontSize(11).Bold();
                        for (int e = 0; e < instr.Examples.Count; e++)
                        {
                            var ex = instr.Examples[e];
                            col.Item().PaddingTop(3).Text(ex.Description).FontSize(8).Italic();
                            col.Item().PaddingTop(1).Background(Colors.Grey.Lighten4).Padding(4)
                                .Text(ex.Code).FontSize(8).FontFamily(Fonts.CourierNew);
                        }
                    }
                });

                page.Footer().AlignCenter().Text(text =>
                {
                    text.Span("ND-100 Processor Reference — Page ").FontSize(8).FontColor(Colors.Grey.Medium);
                    text.CurrentPageNumber().FontSize(8).FontColor(Colors.Grey.Medium);
                });
            });
        }

        private static void GenerateTitlePage(IDocumentContainer container, List<InstructionDefinition> sorted, CpuDefinition? cpuDef)
        {
            container.Page(page =>
            {
                page.Size(PageSizes.A4);
                page.MarginHorizontal(50);
                page.MarginVertical(40);

                page.Content().Column(col =>
                {
                    col.Item().PaddingTop(120).AlignCenter().Text("ND-100").FontSize(48).Bold();
                    col.Item().AlignCenter().Text("Processor Reference Manual").FontSize(24);
                    col.Item().PaddingTop(20).AlignCenter().Text("Norsk Data ND-100 16-bit Minicomputer").FontSize(14);
                    col.Item().PaddingTop(10).AlignCenter().Text($"Generated by NDGen — {DateTime.Now:yyyy-MM-dd}").FontSize(10).FontColor(Colors.Grey.Medium);

                    col.Item().PaddingTop(60).Text("Architecture").FontSize(16).Bold();
                    col.Item().PaddingTop(5).Text(text =>
                    {
                        // From cpu.yaml; the register and addressing tables below are too.
                        text.Line($"Word size: {cpuDef?.Metadata?.WordSize}-bit").FontSize(10);
                        text.Line($"Byte order: {cpuDef?.Metadata?.Endianness}").FontSize(10);
                        text.Line($"Instructions: {sorted.Count}").FontSize(10);
                    });

                    if (cpuDef?.Metadata?.Registers != null)
                    {
                        col.Item().PaddingTop(20).Text("Registers").FontSize(14).Bold();
                        col.Item().PaddingTop(5).Table(table =>
                        {
                            table.ColumnsDefinition(cols =>
                            {
                                cols.ConstantColumn(60);
                                cols.ConstantColumn(50);
                                cols.RelativeColumn();
                            });

                            table.Header(header =>
                            {
                                header.Cell().Background(Colors.Grey.Lighten3).Padding(4).Text("Name").FontSize(9).Bold();
                                header.Cell().Background(Colors.Grey.Lighten3).Padding(4).Text("Size").FontSize(9).Bold();
                                header.Cell().Background(Colors.Grey.Lighten3).Padding(4).Text("Description").FontSize(9).Bold();
                            });

                            var regs = cpuDef.Metadata.Registers;
                            for (int r = 0; r < regs.Count; r++)
                            {
                                var reg = regs[r];
                                var bg = r % 2 == 0 ? Colors.White : Colors.Grey.Lighten5;
                                table.Cell().Background(bg).Padding(3).Text(reg.Name).FontSize(9);
                                table.Cell().Background(bg).Padding(3).Text(reg.Size?.ToString() ?? "16").FontSize(9);
                                table.Cell().Background(bg).Padding(3).Text(reg.Description).FontSize(9);
                            }
                        });
                    }

                    // Addressing modes (operand_types/addressing_modes.yaml)
                    var types = cpuDef?.Metadata?.OperandTypes;
                    OperandType? modes = null;
                    if (types != null)
                        for (int t = 0; t < types.Count; t++)
                            if (types[t].Name == "addressing_modes") modes = types[t];
                    if (modes?.Values != null && modes.Values.Count > 0)
                    {
                        col.Item().PaddingTop(20).Text("Addressing modes").FontSize(14).Bold();
                        col.Item().PaddingTop(5).Table(table =>
                        {
                            table.ColumnsDefinition(cols =>
                            {
                                cols.ConstantColumn(45);
                                cols.RelativeColumn();
                                cols.ConstantColumn(90);
                                cols.ConstantColumn(110);
                            });
                            table.Header(header =>
                            {
                                header.Cell().Background(Colors.Grey.Lighten3).Padding(4).Text("X I B").FontSize(9).Bold();
                                header.Cell().Background(Colors.Grey.Lighten3).Padding(4).Text("Mode").FontSize(9).Bold();
                                header.Cell().Background(Colors.Grey.Lighten3).Padding(4).Text("Form").FontSize(9).Bold();
                                header.Cell().Background(Colors.Grey.Lighten3).Padding(4).Text("Effective address").FontSize(9).Bold();
                            });
                            for (int m = 0; m < modes.Values.Count; m++)
                            {
                                var v = modes.Values[m];
                                var bg = m % 2 == 0 ? Colors.White : Colors.Grey.Lighten5;
                                table.Cell().Background(bg).Padding(3).Text(v.BitPattern ?? "").FontSize(9).FontFamily(Fonts.CourierNew);
                                table.Cell().Background(bg).Padding(3).Text(v.Mode ?? v.Name).FontSize(9);
                                table.Cell().Background(bg).Padding(3).Text(v.Format ?? "").FontSize(9).FontFamily(Fonts.CourierNew);
                                table.Cell().Background(bg).Padding(3).Text(v.EffectiveAddress ?? "").FontSize(9).FontFamily(Fonts.CourierNew);
                            }
                        });
                    }
                });
            });
        }

        /// <summary>
        /// One section per instruction group, in the order of categories.yaml: where the grouping
        /// comes from, its text, and its instructions with their page in this manual.
        /// </summary>
        private void GenerateCategoryPages(IDocumentContainer container, List<InstructionDefinition> sorted, int[] pageStarts)
        {
            var cats = _loader.Categories;
            container.Page(page =>
            {
                page.Size(PageSizes.A4);
                page.MarginHorizontal(50);
                page.MarginVertical(40);
                page.Content().Column(col =>
                {
                    col.Item().Text("Instruction groups").FontSize(20).Bold();
                    for (int c = 0; c < cats.Count; c++)
                    {
                        var cat = cats[c];
                        col.Item().PaddingTop(14).Text(cat.Name).FontSize(14).Bold();
                        for (int r = 0; r < cat.Sources.Count; r++)
                            col.Item().PaddingTop(2).Text("Source: " + DescribeRef(cat.Sources[r])).FontSize(8).FontColor(Colors.Grey.Darken2);
                        if (!string.IsNullOrEmpty(cat.Description))
                            // Markdown in the definitions; Body() puts tables and drawings in a
                            // fixed-width font so their columns line up.
                            Body(col, cat.Description, 9);
                        var members = new StringBuilder();
                        for (int i = 0; i < sorted.Count; i++)
                        {
                            if (sorted[i].Category != cat.Name) continue;
                            if (members.Length > 0) members.Append(", ");
                            members.Append(sorted[i].Name).Append(" (p. ").Append(pageStarts[i]).Append(')');
                        }
                        col.Item().PaddingTop(4).Text("Instructions: " + members).FontSize(9);
                    }
                });
            });
        }

        private static void GenerateTocPage(IDocumentContainer container, List<InstructionDefinition> sorted, int[] pageStarts)
        {
            container.Page(page =>
            {
                page.Size(PageSizes.A4);
                page.MarginHorizontal(50);
                page.MarginVertical(40);

                page.Content().Column(col =>
                {
                    col.Item().Text("Instruction Index").FontSize(20).Bold();
                    col.Item().PaddingTop(5).Text("Instructions are listed alphabetically.")
                        .FontSize(9).FontColor(Colors.Grey.Darken1);

                    col.Item().PaddingTop(10).Table(table =>
                    {
                        table.ColumnsDefinition(cols =>
                        {
                            cols.ConstantColumn(40);
                            cols.ConstantColumn(55);
                            cols.ConstantColumn(65);
                            cols.RelativeColumn();
                            cols.ConstantColumn(55);
                        });

                        table.Header(header =>
                        {
                            header.Cell().Background(Colors.Grey.Lighten3).Padding(2).Text("Page").FontSize(8).Bold();
                            header.Cell().Background(Colors.Grey.Lighten3).Padding(2).Text("Mnemonic").FontSize(8).Bold();
                            header.Cell().Background(Colors.Grey.Lighten3).Padding(2).Text("Opcode").FontSize(8).Bold();
                            header.Cell().Background(Colors.Grey.Lighten3).Padding(2).Text("Description").FontSize(8).Bold();
                            header.Cell().Background(Colors.Grey.Lighten3).Padding(2).Text("Privilege").FontSize(8).Bold();
                        });

                        for (int i = 0; i < sorted.Count; i++)
                        {
                            var instr = sorted[i];
                            var bg = i % 2 == 0 ? Colors.White : Colors.Grey.Lighten5;
                            table.Cell().Background(bg).Padding(2).Text(pageStarts[i].ToString()).FontSize(8);
                            table.Cell().Background(bg).Padding(2).Text(instr.Name).FontSize(8).Bold();
                            table.Cell().Background(bg).Padding(2).Text(instr.Opcode).FontSize(8).FontFamily(Fonts.CourierNew);
                            // The first line of the description is its short form (the name of the
                            // operation); the rest is formulas and detail for the instruction page.
                            var desc = (instr.Description ?? "").Trim();
                            int nl = desc.IndexOf('\n');
                            if (nl >= 0) desc = desc.Substring(0, nl).Trim();
                            table.Cell().Background(bg).Padding(2).Text(desc).FontSize(8);
                            table.Cell().Background(bg).Padding(2).Text(instr.Privilege.ToString().ToLowerInvariant()).FontSize(8);
                        }
                    });
                });
            });
        }

        /// <summary>
        /// Count pages in a PDF by scanning for /Type /Page entries (not /Type /Pages)
        /// </summary>
        private static int CountPdfPages(byte[] pdfBytes)
        {
            var pdfText = Encoding.ASCII.GetString(pdfBytes);
            // Match /Type /Page followed by non-'s' (to exclude /Type /Pages)
            var matches = Regex.Matches(pdfText, @"/Type\s*/Page(?!s)");
            return matches.Count;
        }

        private static void AppendFlag(StringBuilder sb, string flag, string effect)
        {
            if (effect != "unaffected")
            {
                if (sb.Length > 0) sb.Append("  ");
                sb.Append(flag).Append(": ").Append(effect);
            }
        }

        private static void GenerateIndexFile(string idxPath, List<InstructionDefinition> sorted, int[] pageStarts)
        {
            var sb = new StringBuilder();
            sb.AppendLine("# ND-100 Processor Manual Index for Ghidra");
            sb.AppendLine("# Generated by NDGen");
            sb.AppendLine();
            sb.AppendLine("@nd100_manual.pdf [ND-100 Processor Reference Manual (NDGen Generated)]");
            sb.AppendLine();

            for (int i = 0; i < sorted.Count; i++)
            {
                sb.AppendLine($"{sorted[i].Name}, {pageStarts[i]}");
            }

            File.WriteAllText(idxPath, sb.ToString());
        }
    }
}
