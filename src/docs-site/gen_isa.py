"""The instruction-set pages of the documentation site, made from the nd100-definitions YAML.

Called by gen_site.py. Reads the submodule as checked out (nd100-definitions/specs): one page
per instruction file in specs/instructions/, an overview by category, the addressing modes
(specs/operand_types/addressing_modes.yaml) and the status register bits (specs/cpu.yaml).
Every sentence on these pages comes from those files; nothing is written here by hand except
the headings and the "how to read this page" text. A field that a file does not have is left
out of its page, never filled with a placeholder. To improve a page, improve the YAML in the
nd100-definitions repository.

The source links point at the exact nd100-definitions commit this repository pins.
"""
from __future__ import annotations

import glob
import html
import os
import re
import subprocess
import textwrap

import yaml

SPECS = "nd100-definitions/specs"
DEFS_URL = "https://github.com/RetroCoreLabs/nd100-definitions"


def _pinned_commit() -> str:
    try:
        return subprocess.run(["git", "-C", "nd100-definitions", "rev-parse", "HEAD"],
                              capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "main"


def slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def text_md(t: str | None) -> str:
    """YAML prose to Markdown. Indented runs and <ascii-table> blocks become code blocks, so
    formulas and drawn tables keep their columns."""
    if not t:
        return ""
    t = textwrap.dedent(str(t)).strip("\n")
    t = re.sub(r"[ \t]*<ascii-table>\n(.*?)\n[ \t]*</ascii-table>",
               lambda m: "\n```text\n" + textwrap.dedent(m.group(1)) + "\n```\n", t, flags=re.S)
    out: list[str] = []
    in_fence = False
    in_indent = False
    for ln in t.splitlines():
        if ln.startswith("```"):
            in_fence = not in_fence
            out.append(ln)
            continue
        if in_fence:
            out.append(ln)
            continue
        indented = ln.startswith("    ") or ln.startswith("\t")
        if indented and not in_indent:
            # start an indented run as a fenced block: an indented block right under a
            # paragraph line would otherwise be read as more paragraph
            out += ["", "```text"]
            in_indent = True
        elif not indented and in_indent and ln.strip():
            out += ["```", ""]
            in_indent = False
        if in_indent:
            out.append(ln[4:] if ln.startswith("    ") else ln.lstrip("\t"))
        else:
            # the definitions are written line by line (a formula on its own line, then the
            # sentence); keep each line break instead of running the lines together
            if ln.strip() and out and out[-1].strip() and not out[-1].startswith("```")                     and not re.match(r"\s*([-*]|\d+\.) ", ln):
                out[-1] = out[-1] + "  "
            out.append(ln.rstrip())
    if in_indent:
        while out and not out[-1].strip():
            out.pop()
        out.append("```")
    s = "\n".join(out)
    # "<dr>" in prose would be read as an HTML tag; escape it outside code
    parts = re.split(r"(```.*?```|`[^`]*`)", s, flags=re.S)
    for i in range(0, len(parts), 2):
        parts[i] = parts[i].replace("<", "&lt;")
    return re.sub(r"\n{3,}", "\n\n", "".join(parts)).strip()


def bits_of(spec: str) -> tuple[int, int]:
    a, _, b = str(spec).partition("-")
    hi, lo = int(a), int(b or a)
    return max(hi, lo), min(hi, lo)


def mask_of(m: str | None) -> int:
    return int(str(m).replace("_", ""), 2) if m else 0


def encoding_html(opcode: int, mask: int, operands: list[dict]) -> str:
    """A 16-cell drawing of the instruction word: fixed bits as 0/1, fields named."""
    owner: dict[int, str] = {}
    for op in operands or []:
        if "bits" not in op:
            continue
        hi, lo = bits_of(op["bits"])
        for b in range(lo, hi + 1):
            owner[b] = op.get("name", "")
    head = "".join(f'<th>{b}</th>' for b in range(15, -1, -1))
    cells = []
    b = 15
    while b >= 0:
        if mask >> b & 1:
            cells.append(f'<td class="isa-fixed">{opcode >> b & 1}</td>')
            b -= 1
            continue
        name = owner.get(b, "")
        n = 1
        while b - n >= 0 and not (mask >> (b - n) & 1) and owner.get(b - n, "") == name:
            n += 1
        label = html.escape(name.replace("_", " ")) if name else ""
        cls = "isa-field" if name else "isa-free"
        cells.append(f'<td class="{cls}" colspan="{n}">{label}</td>')
        b -= n
    return ('<div class="isa-enc"><table class="isa-word">\n<thead><tr>' + head + '</tr></thead>\n<tbody><tr>'
            + "".join(cells) + "</tr></tbody>\n</table></div>")


def build(have_specs: bool = True) -> tuple[dict[str, str], list[tuple[str, str]]]:
    """Return ({site path: markdown}, nav entries [(title, site path)])."""
    if not os.path.isdir(os.path.join(SPECS, "instructions")):
        raise SystemExit("nd100-definitions is not checked out: git submodule update --init")
    commit = _pinned_commit()
    cpu = yaml.safe_load(open(os.path.join(SPECS, "cpu.yaml"), encoding="utf-8"))
    meta = cpu.get("metadata", cpu)
    classes = {c["name"]: c for c in meta.get("instruction_classes", [])}
    sts = next((r for r in meta.get("registers", []) if r.get("name") == "STS"), {})
    flags = {f["name"]: f for f in sts.get("bits", [])}

    insns = []
    for f in sorted(glob.glob(os.path.join(SPECS, "instructions", "*.yaml"))):
        if os.path.basename(f).startswith("_"):
            continue
        d = yaml.safe_load(open(f, encoding="utf-8"))["instruction"]
        d["_file"] = os.path.relpath(f, "nd100-definitions").replace("\\", "/")
        insns.append(d)

    pages: dict[str, str] = {}
    by_cat: dict[str, list[dict]] = {}
    for d in insns:
        cat = str(d.get("category") or "Other").strip().replace("_", " ")
        by_cat.setdefault(cat, []).append(d)
    used = {}
    for d in insns:
        s = slug(str(d["name"]))
        if s in used:
            s = s + "-" + slug(os.path.splitext(os.path.basename(d["_file"]))[0])
        used[s] = d
        d["_slug"] = s

    for d in insns:
        name = str(d["name"])
        desc = text_md(d.get("description"))
        summary, _, rest = desc.partition("\n\n")
        summary = summary.replace("\n", " ").strip()
        cls = classes.get(d.get("instruction_class") or "")
        operands = d.get("operands") or (cls or {}).get("operands") or []
        mask = mask_of(d.get("mask") or (cls or {}).get("mask"))
        try:
            opcode = int(str(d["opcode"]), 8)
        except ValueError:
            opcode = 0
        cat = str(d.get("category") or "Other").strip().replace("_", " ")
        L = [f"<!-- generated by src/docs-site/gen_isa.py from nd100-definitions/{d['_file']} -->",
             f"# {name}", ""]
        if summary:
            L += [f"**{summary}**", ""]
        rows = [("Opcode", f"`{d['opcode']}` (octal)")]
        if mask:
            rows.append(("Fixed bits (mask)", f"`{mask:016b}`"))
        if d.get("format"):
            rows.append(("Assembler format", "`" + str(d["format"]).strip() + "`"))
        rows.append(("Category", f"[{cat}](index.md#{slug(cat)})"))
        if cls:
            rows.append(("Instruction class", str(cls["name"]).replace("_", " ")))
        if d.get("privilege"):
            p = str(d["privilege"]).strip()
            rows.append(("Privilege", "privileged (operating system and RT programs only)"
                         if p.lower().startswith("priv") else p))
        if d.get("flags_affected"):
            fl = []
            for x in d["flags_affected"]:
                x = str(x)
                fd = flags.get(x)
                # only a real STS bit gets a link; S, for one, is the sign of a result, not a bit
                fl.append(f"[{x}](status-flags.md#{slug(x)}) ({fd['description']})" if fd else x)
            rows.append(("Status flags changed", ", ".join(fl)))
        if d.get("inline_words"):
            rows.append(("Data words after it", str(d["inline_words"])))
        if d.get("isalias"):
            rows.append(("Alias", "another name for an encoding that has its own page"))
        L += ["| Property | Value |", "|---|---|"] + [f"| {a} | {b} |" for a, b in rows] + [""]

        L += ["## Encoding", "", encoding_html(opcode, mask, operands), ""]
        if d.get("bit_format"):
            L += ["```text", textwrap.dedent(str(d["bit_format"])).strip("\n"), "```", ""]
        if operands:
            L += ["| Field | Bits | Meaning |", "|---|---|---|"]
            for op in operands:
                L.append(f"| {op.get('name', '')} | {op.get('bits', '')} | "
                         f"{text_md(op.get('description')).replace(chr(10), ' ').replace('|', '&#124;')} |")
            L.append("")
            for op in operands:
                if op.get("enum"):
                    L += [f"Values of **{op.get('name')}** (octal):", "",
                          "| Value | Name | Meaning |", "|---|---|---|"]
                    for e in op["enum"]:
                        L.append(f"| {e.get('value', '')} | {e.get('name', '')} | "
                                 f"{text_md(e.get('description')).replace(chr(10), ' ').replace('|', '&#124;')} |")
                    L.append("")
                elif op.get("type") in ("addressing_mode", "addressing_modes"):
                    L += [f"The **{op.get('name')}** field is one of the "
                          f"[addressing modes](addressing-modes.md).", ""]
        if rest.strip():
            L += ["## What it does", "", rest.strip(), ""]
        for key, title in (("detailed_description", "In detail"),
                           ("extended_description", "More"), ("before_use", "Before use")):
            if d.get(key):
                L += [f"## {title}", "", text_md(d[key]), ""]
        if d.get("examples"):
            L += ["## Examples", ""]
            for ex in d["examples"]:
                if isinstance(ex, dict):
                    if ex.get("description"):
                        L += [text_md(ex["description"]), ""]
                    if ex.get("code"):
                        L += ["```text", str(ex["code"]).rstrip(), "```", ""]
                else:
                    L += ["```text", str(ex).rstrip(), "```", ""]
        if d.get("exits"):
            L += ["## Where execution continues", "",
                  "| Continues at | When | Condition |", "|---|---|---|"]
            for x in d["exits"]:
                at = (f"the next word" if x.get("offset") == 1 else
                      f"{x['offset']} words on" if "offset" in x else str(x.get("target", "")).replace("_", " "))
                L.append(f"| {at} | {x.get('when', '')} | {text_md(x.get('condition')).replace(chr(10), ' ').replace('|', '&#124;')} |")
            L.append("")
            if d.get("exits_source"):
                L += [f"Source of this: {html.escape(str(d['exits_source']))}.", ""]
        L += [f"*Defined in [{d['_file']}]({DEFS_URL}/blob/{commit}/{d['_file']}) "
              f"in the nd100-definitions repository.*", ""]
        pages[f"isa/{d['_slug']}.md"] = "\n".join(L)

    # overview
    O = ["<!-- generated by src/docs-site/gen_isa.py -->", "# The ND-100 instruction set", "",
         f"All {len(insns)} instructions defined in the "
         f"[nd100-definitions]({DEFS_URL}) repository, by category. The same definitions build "
         "the Ghidra plugin's disassembler, so what is written here is what the plugin decodes.",
         "", "Numbers are **octal**, as in every Norsk Data manual. Each page draws the 16-bit "
         "instruction word: a 0 or 1 is a fixed bit, a named box is a field that the "
         "assembler fills in.", "",
         "See also: [addressing modes](addressing-modes.md) · [status flags](status-flags.md)", ""]
    for cat in sorted(by_cat):
        O += [f"## {cat} {{#{slug(cat)}}}", "", "| Instruction | Opcode | What it does |", "|---|---|---|"]
        for d in sorted(by_cat[cat], key=lambda x: str(x["name"])):
            first = text_md(d.get("description")).split("\n\n")[0].replace("  \n", " ").replace("\n", " ").replace("|", "&#124;")
            priv = " *(privileged)*" if str(d.get("privilege", "")).lower().startswith("priv") else ""
            O.append(f"| [{d['name']}]({d['_slug']}.md) | `{d['opcode']}` | {first}{priv} |")
        O.append("")
    pages["isa/index.md"] = "\n".join(O)

    am = yaml.safe_load(open(os.path.join(SPECS, "operand_types", "addressing_modes.yaml"), encoding="utf-8"))
    A = ["<!-- generated by src/docs-site/gen_isa.py -->", "# Addressing modes", "",
         text_md(am.get("description")), "",
         "Memory transfer instructions carry three mode bits (X, I, B) and an 8-bit signed "
         "displacement. The mode decides how the effective address is formed.", "",
         "| Bits X I B | Mode | Assembler form | Example | Effective address |", "|---|---|---|---|---|"]
    for v in am.get("values", []):
        A.append(f"| `{v.get('bit_pattern', '')}` | {v.get('mode', '')} | "
                 f"`{v.get('format', '')}` | `{v.get('example', '')}` | `{v.get('effective_address', '')}` |")
    pages["isa/addressing-modes.md"] = "\n".join(A) + "\n"

    S = ["<!-- generated by src/docs-site/gen_isa.py -->", "# Status flags", "",
         "The bits of the status register STS, from `specs/cpu.yaml`. Instruction pages link "
         "here for the flags they change.", "",
         "| Bit | Name | Meaning |", "|---|---|---|"]
    for fbit in sorted(sts.get("bits", []), key=lambda x: x.get("position", 0)):
        pos = fbit.get("position", "")
        size = fbit.get("size", 1)
        where = f"{pos}" if size == 1 else f"{pos}-{pos + size - 1}"
        S.append(f"| {where} | <span id=\"{slug(fbit['name'])}\"></span>{fbit['name']} | {fbit.get('description', '')} |")
    pages["isa/status-flags.md"] = "\n".join(S) + "\n"

    nav = [("Overview", "isa/index.md"), ("Addressing modes", "isa/addressing-modes.md"),
           ("Status flags", "isa/status-flags.md")]
    cats = []
    for cat in sorted(by_cat):
        cats.append((cat, [(str(d["name"]), f"isa/{d['_slug']}.md")
                           for d in sorted(by_cat[cat], key=lambda x: str(x["name"]))]))
    return pages, nav + cats
